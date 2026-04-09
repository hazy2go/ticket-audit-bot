// Ticket Audit Bot — read-only probe for Discord ticket leak vectors.
//
// Runs 5 checks against a guild's ticket channels and posts a report:
//   [1] per-user permission_overwrites on ticket channels  (the big leak)
//   [2] roles that hold VIEW_AUDIT_LOG
//   [3] recent CHANNEL_OVERWRITE_CREATE entries targeting users
//   [4] first-message @mention leak
//   [5] @everyone ViewChannel deny on ticket categories
//
// The bot NEVER writes, edits, or deletes. It only reads.

import 'dotenv/config';
import {
  Client,
  GatewayIntentBits,
  PermissionsBitField,
  AuditLogEvent,
  ChannelType,
  EmbedBuilder,
} from 'discord.js';

const {
  BOT_TOKEN,
  GUILD_ID,
  TICKET_CATEGORY_IDS = '',
  REPORT_CHANNEL_ID = '',
  AUDIT_INTERVAL_MS = '21600000', // 6h
  AUDIT_ONCE = '',
} = process.env;

if (!BOT_TOKEN) throw new Error('Missing BOT_TOKEN');
if (!GUILD_ID) throw new Error('Missing GUILD_ID');

const categoryAllowlist = new Set(
  TICKET_CATEGORY_IDS.split(',').map((s) => s.trim()).filter(Boolean),
);

const VIEW = PermissionsBitField.Flags.ViewChannel;
const AUDIT = PermissionsBitField.Flags.ViewAuditLog;

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
  ],
});

const isTicketChannel = (ch) => {
  if (ch.type !== ChannelType.GuildText) return false;
  if (categoryAllowlist.size > 0) {
    return ch.parentId && categoryAllowlist.has(ch.parentId);
  }
  const parentName = ch.parent?.name?.toLowerCase() ?? '';
  if (/(ticket|support|modmail)/i.test(parentName)) return true;
  return /^(ticket|support)[-_]/i.test(ch.name);
};

async function runAudit() {
  const startedAt = new Date();
  const report = {
    startedAt,
    tickets: 0,
    v1: { leaky: 0, total: 0, samples: [], clean: [] },
    v2: { roles: [] },
    v3: {
      userTargeted: 0,
      roleTargeted: 0,
      createUserOverwrites: 0,
      createRoleOverwrites: 0,
    },
    v4: { sampled: 0, leaks: 0 },
    v5: { categories: [] },
  };

  const guild = await client.guilds.fetch(GUILD_ID);
  await guild.channels.fetch();
  await guild.roles.fetch();
  // needed so role.members.size is accurate in vector [2]
  try {
    await guild.members.fetch();
  } catch (err) {
    console.warn('members fetch failed (enable Server Members Intent):', err.message);
  }

  const tickets = [...guild.channels.cache.values()].filter(isTicketChannel);
  report.tickets = tickets.length;
  report.v1.total = tickets.length;

  // ─── [1] per-user permission overwrites ────────────────────────────────
  for (const ch of tickets) {
    const userOverwrites = [...ch.permissionOverwrites.cache.values()].filter(
      (o) => o.type === 1,
    );
    if (userOverwrites.length > 0) {
      report.v1.leaky++;
      if (report.v1.samples.length < 5) {
        report.v1.samples.push({
          channel: `#${ch.name} (${ch.id})`,
          owners: userOverwrites.map((o) => o.id),
        });
      }
    } else {
      report.v1.clean.push(`#${ch.name} (${ch.id})`);
    }
  }

  // ─── [2] roles with VIEW_AUDIT_LOG ─────────────────────────────────────
  report.v2.roles = [...guild.roles.cache.values()]
    .filter((r) => r.permissions.has(AUDIT))
    .map((r) => ({ name: r.name, id: r.id, members: r.members.size }));

  // ─── [3] recent audit log overwrite entries ────────────────────────────
  // Two paths leak owners via audit log:
  //   (a) CHANNEL_OVERWRITE_CREATE with target_type=member
  //   (b) CHANNEL_CREATE with embedded permission_overwrites — bots that
  //       create a channel + overwrites in one API call take this path
  //       instead of firing separate overwrite events.
  try {
    const overwriteLogs = await guild.fetchAuditLogs({
      type: AuditLogEvent.ChannelOverwriteCreate,
      limit: 100,
    });
    for (const entry of overwriteLogs.entries.values()) {
      const t = entry.extra?.type;
      if (t === '1' || t === 1) report.v3.userTargeted++;
      else if (t === '0' || t === 0) report.v3.roleTargeted++;
    }
  } catch (err) {
    console.warn('[v3a] overwrite log fetch failed:', err.message);
  }
  try {
    const createLogs = await guild.fetchAuditLogs({
      type: AuditLogEvent.ChannelCreate,
      limit: 100,
    });
    for (const entry of createLogs.entries.values()) {
      // only count channels that landed in a ticket category
      const createdChannel = guild.channels.cache.get(entry.targetId);
      if (!createdChannel || !isTicketChannel(createdChannel)) continue;
      const owChange = entry.changes?.find(
        (c) => c.key === 'permission_overwrites',
      );
      const overwrites = owChange?.new ?? [];
      for (const ow of overwrites) {
        // type 1 = member, 0 = role (same scheme as channel overwrites)
        if (ow.type === 1 || ow.type === '1') report.v3.createUserOverwrites++;
        else if (ow.type === 0 || ow.type === '0') report.v3.createRoleOverwrites++;
      }
    }
  } catch (err) {
    console.warn('[v3b] channel-create log fetch failed:', err.message);
  }

  // ─── [4] first-message @mention leak (sample up to 25) ────────────────
  const sample = tickets.slice(0, 25);
  report.v4.sampled = sample.length;
  for (const ch of sample) {
    try {
      const msgs = await ch.messages.fetch({ limit: 1, after: '0' });
      const first = msgs.first();
      if (first && first.mentions.users.size > 0) report.v4.leaks++;
    } catch {}
  }

  // ─── [5] @everyone ViewChannel on ticket categories ────────────────────
  const catIds = new Set(tickets.map((c) => c.parentId).filter(Boolean));
  for (const catId of catIds) {
    const cat = guild.channels.cache.get(catId);
    const ow = cat?.permissionOverwrites.cache.get(guild.roles.everyone.id);
    const denied = Boolean(ow?.deny.has(VIEW));
    report.v5.categories.push({ name: cat?.name ?? catId, id: catId, denied });
  }

  return report;
}

function printReport(r) {
  console.log(`\n=== Ticket Audit @ ${r.startedAt.toISOString()} ===`);
  console.log(`Ticket channels found: ${r.tickets}\n`);

  console.log(`[1] user-type overwrites: ${r.v1.leaky}/${r.v1.total}`);
  for (const s of r.v1.samples) {
    console.log(`    LEAK ${s.channel} → ${s.owners.join(', ')}`);
  }
  if (r.v1.clean.length > 0) {
    console.log(`    clean channels:`);
    for (const c of r.v1.clean) console.log(`      ${c}`);
  }

  console.log(`\n[2] roles with VIEW_AUDIT_LOG: ${r.v2.roles.length}`);
  for (const role of r.v2.roles) {
    console.log(`    @${role.name} (${role.members} members, id=${role.id})`);
  }

  console.log(
    `\n[3] audit log leak paths:\n    overwrite_create events: user=${r.v3.userTargeted}, role=${r.v3.roleTargeted}\n    channel_create embedded:  user=${r.v3.createUserOverwrites}, role=${r.v3.createRoleOverwrites}`,
  );

  console.log(
    `\n[4] first-message mention leaks: ${r.v4.leaks}/${r.v4.sampled} sampled`,
  );

  console.log('\n[5] category @everyone ViewChannel deny:');
  for (const c of r.v5.categories) {
    console.log(`    ${c.name}: ${c.denied ? 'denied ✓' : 'NOT denied ⚠'}`);
  }
  console.log('=== end ===\n');
}

function buildEmbed(r) {
  const severity =
    r.v1.leaky > 0 ||
    r.v3.userTargeted > 0 ||
    r.v3.createUserOverwrites > 0
      ? 0xff4d4f
      : r.v4.leaks > 0 || r.v2.roles.length > 3
      ? 0xfaad14
      : 0x52c41a;

  const embed = new EmbedBuilder()
    .setTitle('Ticket Audit Report')
    .setColor(severity)
    .setTimestamp(r.startedAt)
    .setDescription(`Scanned **${r.tickets}** ticket channel(s)`)
    .addFields(
      {
        name: '[1] User permission overwrites',
        value:
          r.v1.leaky === 0
            ? '✓ clean'
            : `⚠ ${r.v1.leaky}/${r.v1.total} channels leak owner via overwrites` +
              (r.v1.samples.length
                ? '\n' +
                  r.v1.samples
                    .map((s) => `• ${s.channel} → <@${s.owners[0]}>`)
                    .join('\n')
                : ''),
      },
      {
        name: '[2] Roles with VIEW_AUDIT_LOG',
        value:
          r.v2.roles.length === 0
            ? '✓ none'
            : r.v2.roles
                .slice(0, 10)
                .map((r2) => `• \`@${r2.name}\` (${r2.members} members)`)
                .join('\n'),
      },
      {
        name: '[3] Audit log leak paths',
        value:
          `overwrite_create: user **${r.v3.userTargeted}** · role **${r.v3.roleTargeted}**\n` +
          `channel_create embedded: user **${r.v3.createUserOverwrites}** · role **${r.v3.createRoleOverwrites}**`,
      },
      {
        name: '[4] First-message mention leak',
        value:
          r.v4.leaks === 0
            ? `✓ clean (sampled ${r.v4.sampled})`
            : `⚠ ${r.v4.leaks}/${r.v4.sampled} sampled tickets ping opener`,
      },
      {
        name: '[5] @everyone ViewChannel deny',
        value:
          r.v5.categories
            .map((c) => `• ${c.name}: ${c.denied ? '✓' : '⚠'}`)
            .join('\n') || 'no ticket categories found',
      },
    );
  return embed;
}

async function runAndReport() {
  try {
    const report = await runAudit();
    printReport(report);
    if (REPORT_CHANNEL_ID) {
      try {
        const ch = await client.channels.fetch(REPORT_CHANNEL_ID);
        if (ch?.isTextBased()) {
          await ch.send({ embeds: [buildEmbed(report)] });
        }
      } catch (err) {
        console.warn('report channel send failed:', err.message);
      }
    }
  } catch (err) {
    console.error('audit failed:', err);
  }
}

client.once('clientReady', async () => {
  console.log(`logged in as ${client.user.tag}`);
  await runAndReport();

  if (AUDIT_ONCE) {
    client.destroy();
    process.exit(0);
  }

  const interval = Number(AUDIT_INTERVAL_MS);
  if (Number.isFinite(interval) && interval > 0) {
    setInterval(runAndReport, interval);
    console.log(`next audit in ${Math.round(interval / 1000 / 60)} min`);
  }
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`\nreceived ${sig}, shutting down`);
    client.destroy();
    process.exit(0);
  });
}

client.login(BOT_TOKEN);
