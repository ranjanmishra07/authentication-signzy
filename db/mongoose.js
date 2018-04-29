const mongoose=require('mongoose');

mongoose.Promise=global.Promise;
mongoose.connect('mongodb://signzy:signzy@ds263707.mlab.com:63707/crudtodo');
// mongoose.connect('mongodb://localhost:/27017/TodoApp');


module.exports={mongoose};
