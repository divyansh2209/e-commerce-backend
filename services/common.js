const passport = require('passport')


exports.isAuth = (req, res, done) => {
    return passport.authenticate('jwt')
}

exports.sanitizeUser = (user) => {
    return {id:user.id , role: user.role}
}

exports.cookieExtractor = function(req) {
    var token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt'];
    }
    token= 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1M2RmNGEyNGUxMDZiYjc4NmE4NjljNSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjk4NTU5MjAzfQ.FJDewJTASMZgoRdyeGpc5OUXIZqompKPZhkx5a1TwCk'
    return token;
};