const { response } = require('express');
const { validationResult } = require('express-validator');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const { generateJWT } = require('../helpers/jwt')

const createUser = async (req, res = response ) =>{


        const { email, password } = req.body;

        try {

            const existEmail = await User.findOne({email});
            if ( existEmail ){
                return res.status(400).json({
                    ok: false,
                    msg: 'Email exist'
                })
            }

            const user = new User( req.body );

            // Ecriptar password
            const salt = bcrypt.genSaltSync();
            user.password = bcrypt.hashSync(password, salt);

            // Genarar JWT
            const token = await generateJWT( user.id )


            await user.save();

            res.json({
                ok: true,
                user, 
                token
            });

        } catch(error){
            console.log(error);
           res.status(500).json({
               ok: false,
               msg: 'Contact with administrator'
           });
        }
    };

const login =async (req, res = response ) => {

    const  { email, password } = req.body;
    try{
        const userDB = await User.findOne({email});
        if(!userDB){
            return res.status(400).json({
                ok: false,
                msg: 'Email not exist'
            });
        }

        const validPassword = bcrypt.compareSync( password, userDB.password );
        if(!validPassword ){
            return res.status(400).json({
                ok: false,
                msg: 'Password is not valid'
            });
        }

        const token = await generateJWT(userDB.id);

        res.json({
            ok: true,
            user: userDB,
            token
        })

    } catch(error){

        console.log(error)
        return res.status(500).json({
            ok: false,
            msg: 'Contact administrator'
        });
    }

}

const renewToken = async(req, res = response) => {
    
    const uid = req.uid;

    const token = await generateJWT(uid);

    const user = await User.findById(uid);

    res.json({
        ok:true,
        user,
        token
    })
}

module.exports = {
    createUser,
    login,
    renewToken
}