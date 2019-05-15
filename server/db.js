const mongoose = require('mongoose');
const config = require('./server.config')
const dbUrl =config.db_url.url

mongoose.connect(dbUrl,{useNewUrlParser:true},err=>err&&console.log(err))

mongoose.model('users', new mongoose.Schema({
    username:String,
    password:String,
}))
module.exports = {
    getModel:function(modelname){
        return mongoose.model(modelname)
    }
} 