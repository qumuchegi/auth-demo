const sessionAuth = (req,res,next)=>{
    if(req.session && req.session.username){
        next()
    }else{
        res.sendStatus(401)
    }
}

module.exports = sessionAuth