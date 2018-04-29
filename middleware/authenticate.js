const {User}=require('./../models/user');
const jwt=require('jsonwebtoken');
//middleware function for accesing profile,updating proffile,logging in user
var authenticate=(req,res,next)=>{
  var token =req.header('x-auth');

  var decoded;
  try{
    decoded=jwt.verify(token,'abc123');
  }catch(e){
     return res.status(401).send(e);
  }
      User.findOne({
    // 'tokens[0].token':token
       "tokens.access":"auth",
       "tokens.token":token
      }).then((user)=>{
    if(!user){
         return res.status(404).send('user not found');
        // return Promise.reject();

    }
    // res.send(user);

    req.user={
      success:true,
      message:'you are authenticated and can visit your profile',

      user:{
        id:user._id,
        name:user.firstname,
        username:user.username,
        email:user.email,
        phone:user.phone,
        gender:user.gender
      }
    };
    req.token=token;
    next();
  }).catch((e)=> {
    res.status(401).send(e);
  });

}
module.exports={authenticate};
