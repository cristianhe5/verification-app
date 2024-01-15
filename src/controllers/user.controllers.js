const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')

const getAll = catchError(async (req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body
    const encriptedpassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        email,
        password: encriptedpassword,
        firstName,
        lastName,
        country,
        image
    });
////////////////////////aqui al crear el nuevo usuario inmediatamente enviamos el codigo de verificacion /////////////////////////
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/verify_email/${code}`;

    //hacmos que se cree un codigo al crear un usuario y que se guarde en la tabla emailCode y lo relacionamos con userId para se ese codigo sea unico para el usuario que creamos
    await EmailCode.create({
        code,
        userId: result.id
    });

    await sendEmail({
        to: email,
        subject: 'Verification email',
        html:`
            <h1>Hello ${firstName} ${lastName}!!</h1>
            <p>Thanks for sing up</p>
            <b>clicks this link to verify your email</b>
            <hr>
            ${link}

        `
    });
    return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if (!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async (req, res) => {
    const { id } = req.params;
    await User.destroy({ where: { id } });
    return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: { id }, returning: true }
    );
    if (result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res)=>{
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({where: {code:code}});
    if(!emailCode) return res.status(401).json({message: "codigo invalido"});
    // const  user = await User.findByPk(emailCode.userId);
    // user.isVerified = true;
    // await user.save();
    const user = await User.update({
        isVerified: true}, 
        {where: {id: emailCode.userId}, returning: true
    });
    await emailCode.destroy();
    return res.json(user);

});

const login = catchError(async(req, res)=>{
    const {email, password}= req.body;
    const user = await User.findOne({where:{email:email}});
    if(!user) return res.status(401).json({message:"invalid credentials"});
    if(!user.isVerified) return res.status(401).json({message:"email not verified"});

    const isValid = await bcrypt.compare(password, user.password);//user.password  es la contrasena que encripte y guarde en la base de datos cuando el usuario hizo sing up

    if(!isValid) return res.status(401).json({message:"invalid credentials"});

    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        {expiresIn: "1d"}
    )
    return res.json({user, token})
}); 

const getLoggedUser = catchError(async(req, res)=>{
    const user = req.user;
    return res.json(user);

})

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    getLoggedUser
}