const express = require('express');
const PORT = process.env.PORT || 3000;


const app = express();

app.locals.pluralize = require('pluralize');

app.set('view engine', 'ejs');
app.use(express.json())
app.set('views', __dirname + '/views')
app.use(express.static(__dirname + '/public'));
app.use(express.urlencoded({extended: false}));


app.get('/', (req, res) => {
    res.render('index', {title: "Home Page", user: req.user});
})


app.get('/auth/login', (req, res) => {
    res.render('auth/login', {title: "Login Page", user: req.user});
})



app.get('/auth/signup', (req, res) => {
    res.render('auth/signup', {title: "Register Page", user: req.user});
})


app.post("/auth/logout", (req, res) => {
    res.redirect('/');
})


app.get('/auth/profile', (req, res) => {
    res.render('auth/profile', {title: "Profile", user: req.user});
})


app.post('/admin/users', (req, res) => {
    res.render('admin/users', {title: "Users", user: req.user});

})


app.use(function(err, req, res, next) {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(err.status || 500);
    res.render('error');
});


app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`App is running on http://localhost:${PORT}`);
});