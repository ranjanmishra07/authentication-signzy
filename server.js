const express=require('express');
const bodyParser=require('body-parser');
const _=require('lodash');
const jwt=require('jsonwebtoken');
const async = require('async');
const crypto=require('crypto');
const nodemailer = require('nodemailer');
const {mongoose}=require('./db/mongoose');
const {pass}=require('./conig');

const {User}=require('./models/user');
const {ObjectId}=require('mongodb');
const {authenticate}=require('./middleware/authenticate');

const app=express();
const port=process.env.PORT || 3000;

app.use(bodyParser.json());



//user post route for registering user
app.post('/user/signup', (req, res) => {
  var body = _.pick(req.body, ['firstname','lastname','username','email', 'password','phone','gender']);
  var user = new User(body);
  user.save().then(() => {
      return user.generateAuthToken();
    }).then((token) => {
      res.header('x-auth', token).send(user);
    }).catch((e) => {
      res.status(400).send(e);
    })
});

//for viewing user profile
app.get('/user/me',authenticate,(req,res)=>{
  res.send(req.user);
})





//for logging in the user after succesfful registration with valid x-auth token
app.post('/user/login',(req,res)=>{
  var body = _.pick(req.body, ['username', 'password']);

  User.findByCredentials(body.username,body.password).then((user)=>{
    user.isActive=true;
    return user.generateAuthToken().then((token) => {
      res.header('x-auth', token).json({success:true,token:token,activity:user.isActive});
    });
  })
  
  .catch((e)=>{res.status(400).send(e)});
})





app.post('/user/signout',authenticate,(req,res)=>{

  
  User.findOne({username:req.body.username}).then((user)=>{
    var access = 'auth';
    var token = jwt.sign({_id: user._id.toHexString(), access}, 'abcddd',{expiresIn:"10d"}).toString();

    user.tokens.token=token
    return user.save().then(() => {
      return token;
    })
    .then(()=>res.send("signed out"))
  })
  
  
  
})

//forgot password

app.post('/user/forgotPassword',function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(3, function(err, buf) {
        var token = buf.toString('hex');
        // var token = Math.floor(Math.random() * 900000) + 100000;
        done(err, token);
      });
    },
    
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          console.log('error', 'No account with that email address exists.');
          res.json({error:true,reason:"no user with this email"})
        
        }
        console.log('step 1')
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
        console.log('step 2')
        


      var smtpTrans = nodemailer.createTransport({
         service: 'Gmail', 
         auth: {
          user: 'ranjan.1js14ec079@gmail.com',
          pass: pass
        }
      });
      var mailOptions = {

        to: user.email,
        from: 'ranjan.1js14ec079@gmail.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            
          'verification token :' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'

      };
      console.log('step 3')

        smtpTrans.sendMail(mailOptions, function(err) {
        res.json({success:true, message:'An e-mail has been sent to ' + user.email +" with further instructions."});
        console.log('sent')
        
});
}
  ], function(err) {
    console.log('this err' + ' ' + err)
    
  });
});


//for verying verification token
app.post('/user/verifyCode', function(req, res) {
  User.findOne({ email:req.body.email,resetPasswordToken: req.body.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      console.log(user);
    if (!user) {
      return res.status(400).json({error:true,message:"restToken is invalid or expires"});
      
    }
    res.status(200).json({success:true,message:"verified"})
  });
});

// for setting actual password
app.post('/user/changePassword', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.body.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user, next) {
        if (!user) {
          return res.status(400).json({ error:'Password reset token is invalid or has expired.'});
          
        }


        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        console.log('password' + user.password  + 'and the user is' + user)

 user.save(function(err) {
  if (err) {
      console.log('error');
      res.send('error while saving')
       
  } else { 
      console.log('here2')
    res.status(200).json({success:true,message:"password changed"})

  }
        });
      });
    }
  ], function(err) {
    res.send('error');
  });
});

app.listen(port,()=>{
  console.log(`started up at ${port}`);
});



module.exports={app};
