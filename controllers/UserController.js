const asyncHandler = require("express-async-handler");
const User = require("../models/UserModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Register User
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // validation

  if (!name || !email || !password) {
    res.status(400);

    throw new Error("Please fill in all required fields ");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("password must be up to six characters");
  }

  // check if user email already exist in the database

  const UserExists = await User.findOne({ email });

  if (UserExists) {
    res.status(400);
    throw new Error("Email has already been registered");
  }

  // create new user in the database
  const user = await User.create({
    name,
    email,
    password,
  });

  // Generate Token
  const token = generateToken(user._id);

  // send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 Day
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, profile, Phone, Bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      profile,
      Phone,
      Bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// login user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  //Validation Request

  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  // check if user exist in the database

  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }

  // user exists, check if password is correct

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  // Generate Token
  const token = generateToken(user._id);

  // send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 Day
    sameSite: "none",
    secure: true,
  
  });

  if (user && passwordIsCorrect) {
    const { _id, name, email, profile, Phone, Bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      profile,
      Phone,
      Bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid Email or Password");
  }
});

module.exports = {
  registerUser,
  loginUser,
};
