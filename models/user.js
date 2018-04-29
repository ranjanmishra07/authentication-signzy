const mongoose=require('mongoose');
const validator=require('validator');
const jwt=require('jsonwebtoken');
const _=require('lodash');
const bcrypt = require('bcryptjs');

var genders='male female'.split(' ');

var UserSchema=new mongoose.Schema({
  firstname:{
    unique:true,
    required:true,
    type:String,
    trim:true
  },
  lastname:{
    required:true,
    type:String,
    trim:true
  },
  username:{
    required:true,
    type:String,
    trim:true
  },
  email:{
    type:String,
    required:true,
    minlength:1,
    trim:true,
    validate:{
      validator:validator.isEmail
    }
  },
  password:{
    type:String,
    required:true,
    minlength:4
  },
    phone: {
       type: String,
       validate: {
         validator: function(v) {
           return /\d{3}\d{3}\d{4}/.test(v);
         },
         message: '{VALUE} is not a valid phone number!'
       },
       required: [true, 'User phone number required']
  },gender: {
    required:true,
    type: String,
     enum: genders
   },
   isActive :{
     type:Boolean,
     default:false
   },
  tokens:[{
    access:{
      type:String,
      required:true
    },
    token:{
      type:String,
      required:true
    }
  }],
  time : { type : Date, default: Date.now },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});



UserSchema.methods.toJSON=function toJSON(){
  var user=this;
  var userObject=user.toObject();
  return _.pick(userObject,['_id','email']);
}

UserSchema.methods.generateAuthToken = function () {
  var user = this;
  var access = 'auth';
  var token = jwt.sign({_id: user._id.toHexString(), access}, 'abc123',{expiresIn:"10d"}).toString();

  user.tokens.push({access, token});

  return user.save().then(() => {
    return token;
  });
};

// UserSchema.statics.findByToken=function(token){
//   var User=this;
//   var decoded;
//   try{
//     decoded=jwt.verify(token,'abc123');
//   }catch(e){
//
//   }
//       User.findOne({
//     '_id':decoded._id,
//     'access':'auth',
//     'token':token
//   })
// }

UserSchema.statics.findByCredentials=function(username,password){
   var User=this;
   return User.findOne({username}).then((user)=>{
     if(!user){
       return Promise.reject("username not valid");
     }

     return new Promise((resolve,reject)=>{
       // Load hash from your password DB.
      bcrypt.compare(password,user.password, function(err, res) {
        // res === true
        if(res){
          resolve(user);
        }
        else{
          reject("E401 password is wrong");
        }
     });
  })
})
}

//hashing of password
UserSchema.pre('save', function(next) {
  var user=this;
  if(user.isModified('password')){
    bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user.password, salt, function(err, hash) {
        // Store hash in password DB.
        user.password=hash;
        next();
    });
});
  }else{
   next();
  }

});

var User=mongoose.model('User',UserSchema);
module.exports={User};
