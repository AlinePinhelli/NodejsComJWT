const passport = require('passport');
const LocalStrategy = require ('passport-local').Strategy;
const BearesStrategy = require ('passport-http-bearer').Strategy;

const Usuario = require('./usuarios-modelo');
const {InvalidArgumentError} =require ('../erros');

const bcrypt = require('bcrypt');
const jwt = require ('jsonwebtoken');

const blacklist = require('../../redis/manipula.blacklist');

function verificaUsuario (usuario){
    if(!usuario){
        throw new InvalidArgumentError('Não existe usuário com esse email ');
    }
}

function verificaSenha (senha,senhaHash){
    const senhaValida = bcrypt.compare (senha, senhaHash);
    if (!senhaValida){
        throw new InvalidArgumentError('E-mail ou senha inválidos');
    }
}
async function verificaTokenNaBlacklist (token) {
    const tokenNaBlacklist = await blacklist.contemToken(token);
    if (tokenNaBlacklist){
    throw new jwt.JsonWebTokenError('Token inválido por logout !');
 }
}


passport.use (
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'senha',
        session:false
    }, async (email,senha,done)=>{
        try{

            const usuario  = await Usuario.buscaPorEmail(email);
            verificaUsuario(usuario);
            await verificaSenha(senha, senhaHash);

            done(null,usuario,{token: token});

        }catch (erro){
           done(erro);
        }
       
    })
);

passport.use(
    new BearesStrategy(
        async (token,done) => {
            try{
                await verificaTokenNaBlacklist(token);
                const payLoad = jwt.verify(token, process.env.CHAVE_JWT);
                const usuario = await Usuario.buscaPorId(payLoad.id);
                done(null, usuario);  

            }catch (erro){
                done(erro);

            }
         
        }
    )
)
