const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors')
const session = require('express-session');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser')

const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const { User } = require('./model/User');
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');
const SECRET_KEY = 'SECRET_KEY';


//JWT options


const opts = {}
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = SECRET_KEY;

//middlewares
server.use(express.static('build'))
server.use(cookieParser())
server.use(session({
    secret: 'keyboard cat',
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
}));
server.use(passport.authenticate('session'));

server.use(cors({
    exposedHeaders: ['X-Total-Count']
}))
server.use(express.json()); // to parse req.body
server.use('/products', isAuth() , productsRouter.router);
server.use('/categories',isAuth() ,  categoriesRouter.router)
server.use('/brands',isAuth() , brandsRouter.router)
server.use('/users', isAuth() ,usersRouter.router)
server.use('/auth', authRouter.router)
server.use('/cart',isAuth() , cartRouter.router)
server.use('/orders',isAuth() , ordersRouter.router)

//Passport Strategy 
passport.use('local',
    new LocalStrategy(
        {usernameField:'email'},
        async function (email, password, done) {
            try {
                const user = await User.findOne(
                    { email: email },
                ).exec();
                if (!user) {
                    done(null, false, { message: 'Invalid Credentials' })
                }

                crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
                    // TODO: this is just temporary, we will use strong password auth
                    if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
                        // TODO: We will make addresses independent of login
                        return done(null, false, { message: 'Invalid Credentials' })
                    }
                    const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
                    done(null, {token});  //this line send to serializer
                })


            } catch (err) {
                done(err)
            }
        }
    ));


passport.use('jwt', new JwtStrategy(opts, async function (jwt_payload, done) {
        console.log({ jwt_payload })
        try {
            const user = await User.findById(jwt_payload.id )
            if(user) {
                return done(null, sanitizeUser(user));
            } else {
                return done(null, false);
                // or you could create a new account
            }
        } catch (error) {
            return done(err, false);
        }
    }));


//creates session variable req.user
passport.serializeUser(function (user, cb) {
    console.log('Serialize', user)

    process.nextTick(function () {
        return cb(null, { id: user.id, role: user.role });
    });
});
//this creates session variable req.user when called from authorized request
passport.deserializeUser(function (user, cb) {
    console.log('De-serialize', user)
    process.nextTick(function () {
        return cb(null, user);
    });
});

main().catch(err => console.log(err));

async function main() {
    await mongoose.connect('mongodb://127.0.0.1:27017/ecommerce');
    console.log('database connected')
}

server.listen(8080, () => {
    console.log('server started')
})
