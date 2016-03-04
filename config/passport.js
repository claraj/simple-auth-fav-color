var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');


module.exports = function(passport) {

  //Passport session setup. Need the ability to
  // serialize (save to disk - a database) and
  // unserialize ( extract from database) sessions.

  // save user in session store.
  passport.serializeUser(function(user, done){
    done(null, user.id);
  });

  //Get user by ID, from session store
  passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user) {
      done(err, user);
    } )
  });


  //Whole world of callbacks.

  //Note the done() method, which has various signatures.

  /*    done(app_err, user_err_or_success, messages);

        done(err);
                means there's been a DB or app error - this is not typical.
                Use to indicates issue with DB or infrastructure or something YOU need to fix.

        done(null, false);
              first parameter is for app error - it's null because this is a *user* error.
              Second parameter is false to indicate USER error in login. e.g. wrong password,
              wrong username, trying to sign up with username that already exists...
              Very common issue, your app will decide how to deal with this.

        done(null, false, msg);
              As before, plus msg parameter to provide error message that app may display to user

        done(null, user);
              Success! null=no app error,
              user = new user object created, or authenticated user object

        done(null, user, msg);
             Variation of the previous call. null=no app error,
             user = new user or authenticated user object,
             msg=messages for app to display to user
   */

  //Sign up new user.

  passport.use('local-signup', new LocalStrategy({
    usernameField : 'username',
    passwordField : 'password',
    passReqToCallback : true
  }, function(req, username, password, done){

    //https://nodejs.org/api/process.html#process_process_nexttick_callback_arg
    //Once the current event loop turn runs to completion, call the callback function.
    process.nextTick(function(){

      //Search for user with this username.
      User.findOne({'local.username' : username}, function(err, user){
        if (err){
          return done(err);    //database error
        }

        //Checking to see if there is already a user with that username
        if (user) {
          console.log('user with that name exists');
          return done(null, false, req.flash('signupMessage', 'Sorry, that username is already taken'));
        }

        //else, the username is available.

        var newUser = new User();
        console.log(username);
        console.log(password);
        newUser.local.username = username;
        newUser.local.password = newUser.generateHash(password);

        newUser.save(function(err){
          if (err) {
            throw err;
          }
          return done(null, newUser)
        })
      })
    })
  }));



  passport.use('local-login', new LocalStrategy({

      usernameField:'username',
      passwordField:'password',
      passReqToCallback : true

    },

    function(req, username, password, done){

      User.findOne({ 'local.username' : username }, function(err, user){

        if (err) {
          return done(err)
        }
        if (!user) {
          return done(null, false, req.flash('loginMessage', 'User not found. IRL, display general login failure.'))
        }
        if (!user.validPassword(password)) {

          return done(null, false, req.flash('loginMessage', 'Wrong password'));
        }

        return done(null, user);
      })

    }))

};