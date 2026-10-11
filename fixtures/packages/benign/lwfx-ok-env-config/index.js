module.exports = {
  production: process.env.NODE_ENV === 'production',
  port: Number(process.env.PORT || 3000),
  debug: Boolean(process.env.DEBUG),
  home: process.env.HOME,
};
