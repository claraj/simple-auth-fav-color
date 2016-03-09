var express = require('express');
var router = express.Router();
var passport = require('passport');


router.get('/', function(req, res, next) {
  //This will probably be the home page for your application
  //Let's redirect to the signup page.
  res.redirect('/login');
});


/* GET signup page */
router.get('/signup', function(req, res, next){
  res.render('signup', { message : req.flash('signupMessage') } )
});


/* POST signup - this is called by clicking signup button on form
*  * Call passport.authenticate with these arguments:
 *    what method to use - in this case, local-signup, defined in /config/passport.js
 *    what to do in event of success
 *    what to do in event of failure
 *    whether to display flash messages to user */
router.post('/signup', passport.authenticate('local-signup', {
  successRedirect: '/secret',
  failureRedirect: '/signup',
  failureFlash :true
}));



/* GET login page */
router.get('/login', function(req, res, next){
  res.render('login', { message : req.flash('loginMessage')})
});


/* POST login - this is called when clicking login button
   Very similar to signup, except using local-login.  */
router.post('/login', passport.authenticate('local-login', {
  successRedirect: '/secret',
  failureRedirect: '/login',
  failureFlash: true
}));


/* GET Logout */
router.get('/logout', function(req, res, next) {
  req.logout();         //passport middleware adds these functions to req.
  res.redirect('/');
});



/* GET secret page. Note isLoggedIn middleware - verify if user is logged in */
router.get('/secret', isLoggedIn, function(req, res, next) {
  res.render('secret', {user : req.user, updateMessage: req.flash('updateMsg') });

});



router.post('/saveSecretInfo', isLoggedIn, function(req, res, next){

  //Since we are letting the user update one or none or both, need to
  //check that there is a value to update.

  var newData = {};

  if (req.body.favoriteColor != '') {
     newData.favoriteColor = req.body.favoriteColor;
  }
  if (req.body.luckyNumber != '') {
    newData.luckyNumber = req.body.luckyNumber;
  }

  //Update our user wih the new data.
  req.user.update(newData, function(err) {
    if (err) {
      console.log('error ' + err);
      req.flash('updateMsg', 'Error updating');
     }

    else {
      console.log('updated');
      req.flash('updateMsg', 'Updated data');
    }

    //Redirect back to secret page, which will fetch and show the updated data.
    res.redirect('/secret');

  })

});




/* Middleware function. If user is logged in, call next - this calls the next
middleware (if any) to continue chain of request processing. Typically, this will
end up with the route handler that uses this middleware being called,
for example GET /secret.

If the user is not logged in, call res.redirect to send them back to the home page
Could also send them to the login or signup pages if you prefer
res.redirect ends the request handling for this request,
so the route handler that uses this middleware (in this example, GET /secret) never runs.

 */
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}



module.exports = router;




