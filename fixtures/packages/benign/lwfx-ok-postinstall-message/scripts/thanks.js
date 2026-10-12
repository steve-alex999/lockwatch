const isCI = Boolean(process.env.CI);
if (!isCI) {
  console.log('Thank you for installing lwfx-ok-postinstall-message!');
}
