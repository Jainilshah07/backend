const express  = require('express');
const User = require('../models/User');
const router  = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchuser');

const JWT_SECRET = "Harryisagoodb$oy";


// ROUTE 1 Create A user using : POST "/api/auth/createUser" . NO Login Required 
router.post('/createuser', [
    body('name' ,'Enter A Valid Name').isLength({ min: 3 }),
    body('email' ,'Enter A Valid Email').isEmail(),
    body('password' , 'Password must be atleast 5 Characters ').isLength({ min: 5 }),
], async(req, res) => {
    // If there are Errors Return Bad request ,  errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
// Check Wheter the user with this email exists Already
try {
    let user = await User.findOne({email: req.body.email});
    if (user) {
        return res.status(400).json({error: 'Sorry A user with this email already exists '})
    }

    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password, salt);
    //Create A User
    user = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: secPass,
      });
      const data = {
          user : {
              id : user.id
          }
      }
      const authtoken = jwt.sign(data ,JWT_SECRET);
    //   res.json(user)
    res.json({authtoken});
    } catch (error) {
      console.log(error.message);
      res.status(500).send("Some Error Occured ")
    }  
})

//  ROUTE 2 Authenticate A user using : POST "/api/auth/login" . NO Login Required 
router.post('/login', [
    body('email' ,'Enter A Valid Email').isEmail(),
    body('password' ,'Password cannot be blank ').exists(),
], async(req, res) => {
 // If there are Errors Return Bad request ,  errors
 const errors = validationResult(req);
 if (!errors.isEmpty()) {
     return res.status(400).json({ errors: errors.array() });
 }

 const {email ,password } = req.body ;
 try {
     let user = await User.findOne({email});
     if(!user){
         return res.status(400).json({error :"Please try to login with correct credentials"});
     }

     const passwordCompare = await bcrypt.compare(password ,user.password)
     if(!password){
        return res.status(400).json({error :"1Please try to login with correct credentials"});
     }
     const data = {
        user : {
            id : user.id
        }
    }
    const authtoken = jwt.sign(data ,JWT_SECRET);
    res.json({authtoken});
  } catch (error) {
    console.log(error.message);
    res.status(500).send("Internal Sever Error")
  } 
 })

 //  ROUTE 3 Get LoddedIn user Details using : POST "/api/auth/getuser" .Login Required  !
 router.post('/getuser', fetchuser , async (req ,res) => {
 try {
    const userId = req.user.id;
    const user = await User.findById(userId).select("-password");
    res.send(user)
} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal Sever Error");
 }
 })


module.exports = router;
