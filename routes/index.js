var sha256 = require('../public/javascripts/SHA256.js');
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Hash Function' });
});

router.get("/hash/:hashed", function(req, res, next) {
  var result = sha256.sha256(req.params.hashed);
  res.render("hash", { hashed : result});
});

router.post("/hash/submit", function(req, res, next) {
  var toHash = req.body.hash;
  res.redirect("/hash/" + toHash);
});

module.exports = router;
