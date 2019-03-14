var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Hash Function' });
});

router.get("/hash/:hashed", function(req, res, next) {
  res.render("hash", { hashed : req.params.hashed});
});

router.post("/hash/submit", function(req, res, next) {
  var toHash = req.body.hash;
  res.redirect("/hash/" + toHash);
});

module.exports = router;
