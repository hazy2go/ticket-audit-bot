// pm2 config — usage on the Pi:
//   pm2 start ecosystem.config.cjs
//   pm2 save
//   pm2 logs ticket-audit-bot
module.exports = {
  apps: [
    {
      name: 'ticket-audit-bot',
      script: 'index.mjs',
      cwd: __dirname,
      interpreter: 'node',
      autorestart: true,
      max_restarts: 10,
      restart_delay: 5000,
      watch: false,
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
