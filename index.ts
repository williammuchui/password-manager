console.log("Hello via Bun!");
const bcrypt = require("bcrypt");
const cryptoJs = require("crypto-js");

const hashPassword = (password: string):string =>{
    return bcrypt.hashSync(password, 10);
};

const isCorrectPassword = (password: string, passwordHash: string): boolean =>{
    return bcrypt.compareSync(password, passwordHash);
};

const generateRandomPassword =(): string =>{
    return bcrypt.hashSync(Math.random().toString(), 10);
};
const encrypt = (data: string, secretKey: string): string =>{
    return cryptoJs.AES.encrypt(data, secretKey).toString();
};

const decrypt = (cipherText: string, secretKey: string): string =>{
    return cryptoJs.AES.decrypt(cipherText, secretKey).toString(cryptoJs.enc.Utf8);
};
type PasswordsMap = {
    title: string;
    password: string;
};

class User{
    private name: string;
    private email: string;
    private passwordHash: string;
    private secretKey: string;
    private passwords: PasswordsMap[];

    constructor(name:string, email: string,password: string){
        this.name = name;
        this.email = email;
        this.passwordHash = hashPassword(password);
        this.secretKey = hashPassword(generateRandomPassword());
        this.passwords = [];
    }
    public getName(): string{
        return this.name;
    }
    public getEmail(): string{
        return this.email;
    }

    public getPasswordHash():string{
        return this.passwordHash;
    }
    public getPassword(title: string): PasswordsMap | undefined{
        for (const password of this.passwords){
            if( password.title === title){
                return {title: password.title, password: decrypt(password.password, this.secretKey)};
            }
        }
        return undefined;
    }
    public getPasswords(): PasswordsMap[]{
        const decryptedPasswords = this.passwords.map((password) =>{
            return {
                ...password,
                password: decrypt(password.password, this.secretKey),
            };
        });
        return decryptedPasswords;
    }
    
    public setName(name: string): void{
        this.name = name;
        return;
    }
    public setEmail(email: string): void{
        this.email = email;
        return;
    }
    public addPassword(title: string): void{
        const password = generateRandomPassword();
        const encryptedPassword = encrypt(password, this.secretKey);
        const data: PasswordsMap = {
            title: title,
            password: encryptedPassword,
        };
        this.passwords.push(data);
        return;
    }
    public validatePassword(password: string): boolean{
        return isCorrectPassword(password, this.passwordHash);
    }
}

const user1 = new User("mike", "mike@me.com","This_is_my_master_p@ssw0rd!");
user1.addPassword("password1");
user1.addPassword("password2");
console.log(user1.getPasswords());
console.log(user1.getPassword("password1"));
