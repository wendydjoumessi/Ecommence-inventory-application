const asyncHandler = require("express-async-handler");
const User = require("../models/UserModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

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
// logout user
const logout = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "successfully logged out" });
});

// Get User Data

const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, profile, Phone, Bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      profile,
      Phone,
      Bio,
    });
  } else {
    res.status(400);
    throw new Error("User not found");
  }
});

// get login status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  // verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }

  return res.json(false);
});

//update user
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, profile, Phone, Bio } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.Phone = req.body.Phone || Phone;
    user.Bio = req.body.Bio || Bio;
    user.profile = req.body.profile || profile;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      profile: updatedUser.profile,
      Phone: updatedUser.Phone,
      Bio: updatedUser.Bio,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

//change password
const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  const { OldPassword, password } = req.body;
  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }

  //validation

  if (!OldPassword || !password) {
    res.status(400);
    throw new Error("please add  old and new password");
  }

  // check if old password matches password in DB
  const passwordIsCorrect = await bcrypt.compare(OldPassword, user.password);

  //save new pasword
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).send("password was changed successfully");
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }
});

// forgot password function
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email }); // check if email exist in our database

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  //Delete token if it exist in the database
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }
  // create Reset token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hashed token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //save Token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
  }).save();

  //construct Reset url

  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  //reset email
  const message = `<h2>Hello ${user.name}</h2>
    <p>please use the url below to reset your password</p>
    <p>This reset lik is valid for 30 minutes</p>
    <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

    <p>Regards</P>
     <p>Ecommerce Team</P>
    `;

  const subject = "Password Reset Request";
  const send_to = user.email;
  const send_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, send_from);
    res.status(200).json({ success: true, message: "Reset Email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not send please try again");
  }
});

//reset password

const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  // Hashed token then compare to token in the DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  //find token in the DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid od Expires Token");
  }

  //Find User
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: " Password reset successful please login",
  });
});

module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
