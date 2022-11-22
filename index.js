const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 30000;
// ========  middleware  ========
app.use(cors());
app.use(bodyParser.json());
// ==============================
const users = [
    {
        id: 1,
        username: 'harry',
        password: 'harry123',
        isAdmin: true
    },
    {
        id: 2,
        username: 'ron',
        password: 'ron123',
        isAdmin: false
    },
];

let refreshTokens = []; // can use any database or redis cache to store this access token;

app.get('/', (req, res) =>{
    res.send('Lumos maxima..')
});

app.post('/api/refresh', (req, res)=>{
    // take refresh token from the user;
    const refreshToken = req.body.token;

    // send error if there isn't any token or it's invalid;
    if(!refreshToken){ res.status(401).send("You're not authenticated")}
    if(!refreshTokens.includes(refreshToken)){ res.status(403).send("Refresh token is not valid")}

    jwt.verify(refreshToken, 'myRefreshSecretKey', (err, data)=>{
        err && console.log(err);
        refreshTokens = refreshTokens.filter(token=> token !== refreshToken);  // if it's not a match then it'll stay otherwise it'll b deleted
        
        // if everything is ok, create new access token, refresh token and send to user;
        const newAccessToken = generateAccessToken(data);  // data is payload;
        const newRefreshToken = generateRefreshToken(data);  // data is payload;

        refreshTokens.push(newRefreshToken);
        res.status(200).send({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })

    })

})

const generateAccessToken = (user)=>{
    return jwt.sign({id: user.id, isAdmin: user.isAdmin}, 'mySecretKey', { expiresIn: '5s'})
}
const generateRefreshToken = (user)=>{
    return jwt.sign({id: user.id, isAdmin: user.isAdmin}, 'myRefreshSecretKey')
}

app.post('/api/login', (req, res) =>{
    const {username, password} = req.body;
    const user = users.find(u=>{
        return u.username === username && u.password === password;
    });
    if(user){
        // Generate an access token;
        // const accessToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, 'mySecretKey', { expiresIn: '15m'});
        // const refreshToken = jwt.sign({id: user.id, isAdmin: user.isAdmin}, 'myRefreshSecretKey', { expiresIn: '15m'});
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshTokens.push(refreshToken);

        res.send({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    }else{
        res.send('username or password incorrect!')
    }
});

const verify = (req, res, next)=>{
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(' ')[1];
        jwt.verify(token, 'mySecretKey', (err, payload)=>{
            if(err){res.status(403).send('token is not valid!')};

            req.payload = payload;
            next();
        });
    }
    else{
        res.status(401).send('not authenticated!')
    }
}

app.delete('/api/users/:userId', verify, (req, res)=>{
    const userId = parseInt(req.params.userId);
    if(req.payload.id === userId || req.payload.isAdmin){
        res.status(200).send('User is deteted!')
    }else{
        res.status(403).send('You are not allowed to delete this user!')
    }
})

app.post('/api/logout', verify, (req, res)=>{
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken)
    res.status(200).send('You loggedout successfully')
})

app.listen(port, ()=>{
    console.log('running..');
});