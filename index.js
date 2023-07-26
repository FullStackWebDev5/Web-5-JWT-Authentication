const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
dotenv.config()

const app = express()

const isAuthenticated = (req, res, next) => {
  try {
    const user = jwt.verify(req.headers.token, process.env.JWT_SECRET)
    req.user = user
    next()
  } catch (error) {
    res.json({
      status: 'FAIL',
      message: 'Please login first!'
    })
  }
}

const isAdmin = (req, res, next) => {
  console.log(req.user)
  if(req.user.isAdmin) {
    next()
  } else {
    res.json({
      status: 'FAIL',
      message: "You're not allowed to access this page"
    })
  }
}


app.use(bodyParser.urlencoded({ extended: false }))
app.use(express.static('./public'))

app.set('view engine', 'ejs')

const User = mongoose.model('User', {
  firstName: String,
  lastName: String,
  email: String,
  password: String,
  isAdmin: Boolean
})

app.get('/', (req, res) => {
  res.json({
    status: 'SUCCESS',
    message: 'All good!'
  })
})

app.get('/signup', (req, res) => {
  res.render('signup')
})

app.get('/login', (req, res) => {
  res.render('login')
})

app.get('/dashboard', isAuthenticated, (req, res) => {
  res.render('dashboard')
})

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  res.render('admin')
})

/* -------------------------------- */
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, isAdmin } = req.body
    
    const user = await User.findOne({ email })
    if(user) {
      return res.json({
        status: 'FAIL',
        message: 'User with the given email address already exists. Please login instead.'
      })
    }

    const encryptedPassword = await bcrypt.hash(password, 10)
    const newUser = { 
      firstName, 
      lastName, 
      email, 
      password: encryptedPassword, 
      isAdmin 
    }
    await User.create(newUser)
    const jwToken = jwt.sign(newUser, process.env.JWT_SECRET, { expiresIn: 60 })
    res.json({
      status: 'SUCCESS',
      message: "You've signed up successfully",
      jwToken
    })
  } catch (error) {
    res.json({
      status: 'FAIL',
      message: 'Something went wrong'
    })
  }
})

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await User.findOne({ email })
    if(user) {
      const passwordMatched = await bcrypt.compare(password, user.password)
      if(passwordMatched) {
        const jwToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET, { expiresIn: 60 })
        res.json({
          status: 'SUCCESS',
          message: "You've logged in successfully",
          jwToken
        })
      } else {
      res.json({
        status: 'FAIL',
        message: 'Incorrect password'
      })
    }
    } else {
      res.json({
        status: 'FAIL',
        message: 'User does not exist'
      })
    }
  } catch (error) {
    console.log(error)
    res.json({
      status: 'FAIL',
      message: 'Something went wrong'
    })
  }
})

app.listen(process.env.PORT, () => {
  mongoose
    .connect(process.env.MONGODB_URL)
    .then(() => console.log(`Server running on http://localhost:${process.env.PORT}`))
    .catch((error) => console.log({ error }))
})












/*
  ## Authentication vs Authorization
  - Authentication: Verify user's identity (Who are you?)
  - Authorization: Checking the access of logged in user (What access do you have?)

  ## bcrypt - Encrypt the password
  ## JWT (JSON Web Token)

  Image: https://www.vaadata.com/blog/wp-content/uploads/2016/12/JWT_tokens_EN.png
*/