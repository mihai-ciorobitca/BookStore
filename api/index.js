require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const ejs = require('ejs');
const path = require('path');
const session = require('express-session');  // Import express-session
const app = express();

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const SECRET_KEY = process.env.SECRET_KEY;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration';

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Setup view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Setup session middleware
app.use(session({
    secret: SECRET_KEY || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set to true if using HTTPS
}));

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    cart: [{ name: String, quantity: Number }]
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
    name: String,
    price: Number,
    stock: Number
});
const Product = mongoose.model('Product', ProductSchema);

app.get('/', async (req, res) => {
    try {
        const products = await Product.find();
        const user = req.session.user ? req.session.user : null;
        const success = req.session.success ? req.session.success : null;
        const error = req.session.error ? req.session.error : null;
        res.render('index', { 
            products, 
            user,
            success,
            error,
            session: req.session
        });
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.json({ status: 'fail', message: 'Incorrect username or password' });
    }
    req.session.user = username;
    res.json({ status: 'success', route: '/' });
});

app.get('/google/login', async (req, res) => {
    const googleProviderConfig = (await axios.get(GOOGLE_DISCOVERY_URL)).data;
    const authorizationEndpoint = googleProviderConfig.authorization_endpoint;
    const redirectUri = `${req.protocol}://${req.get('host')}/google/login/callback`;
    const requestUri = `${authorizationEndpoint}?response_type=code&client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&scope=openid%20email%20profile`;
    res.redirect(requestUri);
});

app.get('/google/login/callback', async (req, res) => {
    const { code } = req.query;
    const googleProviderConfig = (await axios.get(GOOGLE_DISCOVERY_URL)).data;
    const tokenEndpoint = googleProviderConfig.token_endpoint;
    const redirectUri = `${req.protocol}://${req.get('host')}/google/login/callback`;

    const tokenResponse = await axios.post(tokenEndpoint, new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
    }).toString(), {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    const idToken = tokenResponse.data.id_token;
    const userinfoEndpoint = googleProviderConfig.userinfo_endpoint;
    const userinfoResponse = await axios.get(userinfoEndpoint, {
        headers: {
            Authorization: `Bearer ${idToken}`
        }
    });

    const { email } = userinfoResponse.data;
    const user = await User.findOne({ email });
    if (user) {
        req.session.user = user.username;
        return res.redirect('/');
    }
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, password, email, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        return res.json({ status: 'fail', message: 'Passwords do not match' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
        return res.json({ status: 'fail', message: 'Username or email already registered' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    await User.create({ username, password: hashedPassword, email });
    res.json({ status: 'success', message: 'Successfully created account! You can now log in' });
});

app.get('/admin', (req, res) => {
    if (req.session.admin) {
        res.render('admin');
    } else {
        res.redirect('/login');
    }
});

app.get('/admin/users', async (req, res) => {
    if (req.session.admin) {
        const users = await User.find();
        res.render('manage_users', { users });
    } else {
        res.redirect('/login');
    }
});

app.post('/admin/users/delete/:userId', async (req, res) => {
    if (req.session.admin) {
        await User.findByIdAndDelete(req.params.userId);
        res.redirect('/admin/users');
    } else {
        res.redirect('/login');
    }
});

app.post('/admin/users/change_password/:userId', async (req, res) => {
    if (req.session.admin) {
        const { newPassword } = req.body;
        const hashedPassword = bcrypt.hashSync(newPassword, 8);
        await User.findByIdAndUpdate(req.params.userId, { password: hashedPassword });
        res.redirect('/admin/users');
    } else {
        res.redirect('/login');
    }
});

app.get('/admin/products', async (req, res) => {
    if (req.session.admin) {
        const products = await Product.find();
        res.render('manage_products', { products });
    } else {
        res.redirect('/login');
    }
});

app.post('/admin/products/update/:productId', async (req, res) => {
    if (req.session.admin) {
        const { name, price, stock } = req.body;
        await Product.findByIdAndUpdate(req.params.productId, { name, price, stock });
        res.redirect('/admin/products');
    } else {
        res.redirect('/login');
    }
});

app.get('/about', (req, res) => {
    res.render('about');
});

app.get('/cart', async (req, res) => {
    if (req.session.user) {
        const user = await User.findOne({ username: req.session.user });
        const products = user ? user.cart : [];
        res.render('cart', { username: req.session.user, products });
    } else {
        res.redirect('/login');
    }
});

app.post('/cart/add-cart', async (req, res) => {
    if (req.session.user) {
        const { product_name } = req.body;
        const user = await User.findOne({ username: req.session.user });
        if (user) {
            const existingProduct = user.cart.find(item => item.name === product_name);
            if (existingProduct) {
                existingProduct.quantity += 1;
                await User.updateOne(
                    { username: req.session.user, 'cart.name': product_name },
                    { $set: { 'cart.$.quantity': existingProduct.quantity } }
                );
            } else {
                await User.updateOne(
                    { username: req.session.user },
                    { $push: { cart: { name: product_name, quantity: 1 } } }
                );
            }
            res.json({ status: 'success', message: 'Product added successfully', route: '/cart' });
        }
    } else {
        res.json({ status: 'error', message: 'User not logged in' });
    }
});

app.post('/cart/increase-cart', async (req, res) => {
    if (req.session.user) {
        const { product_name } = req.body;
        await User.updateOne(
            { username: req.session.user, 'cart.name': product_name },
            { $inc: { 'cart.$.quantity': 1 } }
        );
        res.json({ status: 'success', message: 'Quantity increased successfully', route: '/cart' });
    }
});

app.post('/cart/decrease-cart', async (req, res) => {
    if (req.session.user) {
        const { product_name } = req.body;
        const user = await User.findOne({ username: req.session.user, 'cart.name': product_name });
        if (user) {
            const cartItem = user.cart.find(item => item.name === product_name);
            if (cartItem.quantity > 1) {
                await User.updateOne(
                    { username: req.session.user, 'cart.name': product_name },
                    { $inc: { 'cart.$.quantity': -1 } }
                );
            } else {
                await User.updateOne(
                    { username: req.session.user },
                    { $pull: { cart: { name: product_name } } }
                );
            }
            res.json({ status: 'success', message: 'Quantity decreased successfully', route: '/cart' });
        }
    }
});

app.post('/cart/remove-cart', async (req, res) => {
    if (req.session.user) {
        const { product_name } = req.body;
        await User.updateOne(
            { username: req.session.user },
            { $pull: { cart: { name: product_name } } }
        );
        res.json({ status: 'success', message: 'Product removed successfully', route: '/cart' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
