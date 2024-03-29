/*
    path: api/login
*/

const { Router } = require('express');
const { check } = require('express-validator');
const { createUser, login, renewToken } = require('../controllers/auth');
const { validateFields } = require('../middlewares/validate-fields');
const { validateJWT } = require('../middlewares/validate-jwt')
const router = Router();

router.post('/new',[

    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Email is required').isEmail(),
    check('password', 'Password is required').not().isEmpty(),

    validateFields

], createUser);

//post:/
// validar email y password
router.post('/',[
    check('email', 'Email is required').isEmail(),
    check('password', 'Passwrod is required').not().isEmpty(),
    validateFields
], login );


//validateJWT,
router.get('/renew', validateJWT,renewToken)

module.exports = router;