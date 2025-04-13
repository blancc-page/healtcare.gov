import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';

export const register = async(req,res) =>{
    const {name, email, password, idNum} = req.body;

    if(!name || !email || !password){
        return res.json({success: false, message: 'User Not Created!'})
    }

    try{
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            res.json({success: false, message: 'User Already Created!'})
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({idNum, name, email, password: hashedPassword});

        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'}); // OTP lifespan supposed to be shorter 

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({success:true});

    } catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async(req,res) => {
    const {idNum, email, password} = req.body;// check this

    if(!email || ! password || !idNum){
        res.json({success: false, message: "Email / ID and Password Are Required!"})
    }

    try {
        const user = await userModel.findOne({$or: [{ email }, { idNum }]}); // check this

        if(!user){
            return res.json({success:false, message: 'Invalid Email / ID'})
        }

        const isMatch = await bcrypt.compare(password, user.password);


        if (!isMatch) {
            return res.json({success:false, message: 'Invalid password'})
        }

        const token = jwt.sign({id: user_id}, process.env.JWT_SECRET, {expiresIn: '1h'}); // OTP lifespan supposed to be shorter 

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({success:true});


    } catch (error) {
        return res.json({success: false, message: error.message});
    }
} 


export const logout = async (req,res) => {
    try {
        res.clearCoockie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict'
        })

        return res.json({sucess: true, message: "User Logged Out"})
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}
