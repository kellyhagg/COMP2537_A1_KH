
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const { emit } = require("process");


const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        <div><button onclick="window.location.href='/signup'">Sign Up</button></div>
        <div><button onclick="window.location.href='/login'">Log In</button></div>
        `;
    } else {
        var html = `
        <div>Hello, ${req.session.username}!</div>
        <div><button onclick="window.location.href='/members'">Go to Members Area</button></div>
        <div><button onclick="window.location.href='/logout'">Logout</button></div>
        `;
    }
    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        var images = ['duck.gif', 'frog.gif', 'spongebob.gif'];
        var index = Math.floor(Math.random() * images.length);
        var html = `
        <h1>Hello, ${req.session.username}!</h1>

        <img src='/public/Screenshot_5.png' width='200px' height='200px'>

        <div><button onclick="window.location.href='/logout'">Logout</button></div>
        `;
    }
    res.send(html);
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>Kelly Hagg</h1>");
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/createUser', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/signupSubmit', (req, res) => {
    var html = `error`;
    var missing = req.query.missing;
    if (missing == 1) {
        var html = `
        Name, email, and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 2) {
        var html = `
        Name and email are required.
        <br><br>
        <a href='/signup'>Try Again</a>    
    `;
    } else if (missing == 3) {
        var html = `
        Name and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>    
    `;
    } else if (missing == 4) {
        var html = `
        Email and password are required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 5) {
        var html = `
        Name is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 6) {
        var html = `
        Email is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    } else if (missing == 7) {
        var html = `
        Password is required.
        <br><br>
        <a href='/signup'>Try Again</a>
    `;
    }
    res.send(html);
});

app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/signup' method='post'>
    <div><input name='username' type='text' placeholder='name'></div>
    <div><input name='email' type='text' placeholder='email'></div>
    <div><input name='password' type='password' placeholder='password'></div>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <div><input name='email' type='text' placeholder='email'></div>
    <div><input name='password' type='password' placeholder='password'></div>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/loginSubmit', (req, res) => {
    var html = `
    Invalid email/password combination.
    <br><br>
    <a href='/login'>Try Again</a>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword });
    console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

app.post('/signup', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (username == '' && email == '' && password == '') {
        console.log("all are empty");
        res.redirect('/signupSubmit?missing=1');
        return;
    } else if (username == '' && email == '') {
        console.log("name and email are empty");
        res.redirect('/signupSubmit?missing=2');
        return;
    } else if (username == '' && password == '') {
        console.log("name and password are empty");
        res.redirect('/signupSubmit?missing=3');
        return;
    } else if (email == '' && password == '') {
        console.log("email and password are empty");
        res.redirect('/signupSubmit?missing=4');
        return;
    } else if (username == '') {
        console.log("name is empty");
        res.redirect('/signupSubmit?missing=5');
        return;
    } else if (email == '') {
        console.log("email is empty");
        res.redirect('/signupSubmit?missing=6');
        return;
    } else if (password == '') {
        console.log("password is empty");
        res.redirect('/signupSubmit?missing=7');
        return;
    }

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(40).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/createUser");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(40).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginSubmit");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/loginSubmit");
        return;
    }
});

app.get('/loggedIn', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


// app.get('/cat/:id', (req, res) => {

//     var cat = req.params.id;

//     if (cat == 1) {
//         res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
//     }
//     else if (cat == 2) {
//         res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
//     }
//     else {
//         res.send("Invalid cat id: " + cat);
//     }
// });


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 