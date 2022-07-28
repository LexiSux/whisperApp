// ---------------------------- ENVIRONMENT VARIABLES --------------------------------------
require('dotenv').config()
// console.log(process.env)

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongooose = require('mongoose');
// cookies & session
const session = require('express-session')
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
// google authentication
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app=express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

// passport----------------------- step 2
app.use(session({
    secret:"Our little secret",
    resave:false,
    saveUninitialized:false
}));

//step 3
app.use(passport.initialize());
app.use(passport.session());

mongooose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongooose.Schema ({
    email: String,
    password: String,
    googleId:String,
    secret:String
});

// --------------------------------------------- ENCRYPTION ------------------------------------------
userSchema.plugin(passportLocalMongoose);  //step 4
userSchema.plugin(findOrCreate);

const User = new mongooose.model("User", userSchema);

// step 5 --------------------------------
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

// google authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {  //it checks whether the id exist on dB or not, if not it creates a new entry
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
    res.render("home");
});

app.get('/auth/google',
passport.authenticate('google', { scope: ["profile"] }));

// google login authentication ------------------------
app.get("/login", function(req,res){
    res.render("login");
}); 

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req,res){
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }
    // else{
    //     res.redirect("/login");
    // }

    //commented earlier part since now we want anyone to view all the listed secrets, not just the logged in user

    User.find({"secret":{$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        }
        else{
            if(foundUsers){
                // console.log(foundUsers);
                res.render("secrets",{userWithSecrets: foundUsers});
            }
        }
    });
});

app.get("/logout", function(req,res){
    req.logout(function(err) {
        if (err) { console.log(err); }
        res.redirect('/');
    });
});

// ------------------ SUBMIT ------------------------------
app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;

    console.log(req.user.id); //to see which user entered the secret 

    User.findById(req.user.id, function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret=submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.post("/register", function(req,res){

    User.register({username:req.body.username},req.body.password, function(err, newRegdUser){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req,res){

    const enteredUser = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(enteredUser, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});



app.listen(process.env.PORT || 3000, function(){
    console.log("server running on port 3000");
})