let express = require('express')
let app = express()
let port = 3000
let database = require('./database.json')
//todo: implement a real database
let bodyParser = require('body-parser')
let cors = require('cors')
let { v4: uuidv4 } = require ('uuid')
let cookie_parser=require('cookie-parser')
let crypto = require('crypto')

app.use(cookie_parser())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Inject the user from cookies to the requests, from then on if req.user
//exists, the user is validated
app.use((req, res, next) => {
    // Get auth token from the cookies
    const authToken = req.cookies['AuthToken'];
    req.user = authTokens[authToken];
    next();
});

//method to hash password before storing
const getHashedPassword = (password) => {
    const sha256 = crypto.createHash('sha256');
    const hash = sha256.update(password).digest('base64');
    return hash;
}

const generateAuthToken = () => {
    return crypto.randomBytes(30).toString('hex');
}

const validateItemInput = (req, res, next) => {
    //todo: validate input
    next()
}

const validateUserInput = (req, res, next) => {
    //todo: validate input
    next()
}

//every api end-point that need authorization will use this middleware
const requireAuth = (req, res, next) => {
    if (req.user) {
        next();
    } else {
        res.status(401).send("Unauthorized.").end();
    }
};

// This will hold the users and authToken related to users (cookie authentication)
const authTokens = {};

// get all items
app.get('/item', (req, res) => {
  res.json(database.items)
  res.status(200).send("Successfully retrieved items")
})

// post new item
app.post('/item',/*authentication*/requireAuth, validateItemInput, (req, res) => {
  var newItem = req.body
  newItem.id = uuidv4()
  //get user info from cookie then add to newItem
  newItem.sellerInfo = {
    firstName: req.user.firstName,
    lastName: req.user.lastName,
    email: req.user.email,
    phone: req.user.phone
  }
  database.items.push(newItem)
  res.status(201).send("New item added")
})

// modify existing item
app.put('/item',/*authentication*/requireAuth, (req, res) => {
  let newItem = req.body
  index = database.items.findIndex(item => item.id === newItem.id)
  database.items[index] = newItem
  console.log(database.items)
  res.status(202).send("item modified")
})

//filter items by location, category, date

app.get('/item/findByStatus', (req, res) => {
  let itemArray = []
  if (req.query.category) {
    itemArray = database.items.filter(item => item.category === req.query.category)
  }

  if (req.query.city) {
    itemArray = itemArray.filter(item => item.city === req.query.city)
  }

  if (req.query.country) {
    itemArray = itemArray.filter(item => item.country === req.query.country)
  }

  if (req.query.date) {
    itemArray = itemArray.filter(item => item.date === req.query.date)
  }
  res.json(itemArray)
  res.status(201).send("ok")
})

app.delete('/item/:itemId',/*authentication*/requireAuth,(req, res) => {
  index = database.items.findIndex((item, index) =>  index == req.params.itemId)
  database.items.slice(index,1)
})

app.post('/item/:itemId/uploadImage',/*authentication*/requireAuth,(req, res) => {
})

//create a new user
app.post('/user',validateUserInput, (req, res) => {
  var newUser = req.body
  // generate unique id
  newUser.id = uuidv4()
  // hash the password
  newUser.password = getHashedPassword(re.body.password)
  database.items.push(newUser)
  console.log(newUser)
  res.status(201).send("user created")
})

app.get('/user/login', (req, res) => {
const { username, password } = req.body;
const hashedPassword = getHashedPassword(password);

const user = database.users.find(u => {
    return u.username === username && hashedPassword === u.password
});

if (user) {
    const authToken = generateAuthToken();
    // Store authentication token
    authTokens[authToken] = user;
    // Setting the auth token in cookies
    res.cookie('AuthToken', authToken);
    // Redirect user to the protected page
    res.status(200).send("User logged in successfully")
} else {
    res.status(400).send("Username/password pair incorrect.")
}
})

app.get('/user/logout', (req, res) => {
  res.clearCookie('AuthToken')
  delete authTokens[authToken]
  if (!authTokens[authToken] && !req.cookies['AuthToken']){
    res.status(200).send("Logout successfully")
  }
})

app.get('/', (req, res) => {
  res.send("welcome")
  res.status(200)
})

app.listen(port, () => {
  console.log(`app listening at port:${port}`)
})
