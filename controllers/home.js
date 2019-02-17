/**
 * GET /
 * Home page.
 */
exports.index = (req, res) => {
  res.render('home', {
    title: 'Home'
  });
};

/**
 * GET /editorial
 * Editorial page.
 */
exports.editorial = (req, res) => {
  res.render('editorial', {
    title: 'Landing Page'
  });
};
