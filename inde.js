const express = require('express');
const http = require('http');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY
const datasecret = process.env.DATA_SECRET;
const { v4: uuidv4 } = require('uuid');
const { forgot, welcome } = require('./email')
const cors = require('cors')
const bodyParser = require('body-parser');
require('dotenv').config
const { getAccount } = require('./account');
app.use(bodyParser.json());

app.use(cors())
app.options('*', cors())

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

function generateUniqueUserID() {
    // Generate a random UUID (version 4)
    const userID = uuidv4();

    return userID;
}

const excludedRoutes = ['/api/v1/login', '/api/v1/signup', '/api/v1/forgot', '/', '/webhooksuccess'];

function authenticateJWT(req, res, next) {
    if (excludedRoutes.includes(req.url)) {

        return next();
    }

    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'Bearer token is missing' });
    }

    try {
        const decodedToken = jwt.verify(token, secretKey);
        req.user = decodedToken;
        console.log('this is', req.user)
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
}

app.use(authenticateJWT)

app.get('/', (req, res) => {
    res.send('Server is working correctly');
});
const dbpassword = process.env.DB_PASSWORD
app.use(express.urlencoded({ extended: false }));
const pool = mysql.createPool({
    host: 'localhost',
    user: 'heydatac_glo',
    password: dbpassword,
    database: 'heydatac_glo',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,

});
const executeQuery = async (query, params) => {
    const db = await pool.getConnection();
    try {
        const [results, fields] = await db.execute(query, params);
        return results;
    } catch (error) {
        console.error('Error executing query:', error.message);
        throw error;
    } finally {
        db.release();
    }
}





const setpayment = async (data) => {
    const { phonenumber, deposit, Status, plan, amount, date } = data;

    try {
        const query = `INSERT INTO transactions (phonenumber, buynumber, status, price, date, network, size) VALUES (?,?,?,?,?,?,?)`;
        const results = await executeQuery(query, [phonenumber, deposit, Status, amount, date, plan, 'Transaction']);
        console.log('successful!', results);
        // Assuming you want to return the results
    } catch (error) {
        console.log('error setting transaction');
        throw error; // Re-throw the error to propagate it
    }
};

const paymentSuccess = async (userid, amount, date) => {
    try {
        const query = `SELECT phonenumber, accountbalance FROM appusers WHERE userid = ?`;
        const results = await executeQuery(query, [userid]);

        if (results.length === 0) {
            throw new Error('User not found');
        }

        const user = results[0];
        const { phonenumber, accountbalance } = user;
        const balance = parseInt(accountbalance, 10);
        const parsedAmount = parseInt(amount, 10);
        const plusedamount = balance + parsedAmount;

        const anotherquery = `UPDATE appusers SET accountbalance = ? WHERE userid = ?`;
        await executeQuery(anotherquery, [plusedamount, userid]);

        const deposit = 'Deposit';
        const Status = 'successful';
        const plan = 'nothing';
        const imade = { phonenumber, deposit, Status, plan, amount, date };

        await setpayment(imade);
        return Status;
    } catch (error) {
        console.error('Error in paymentSuccess:', error);
        return 'failed';
    }
};




const processedTransactions = new Set();

app.post('/webhooksuccess', async (req, res) => {
    const monnifySignature = req.get('monnify-signature');
    if (!monnifySignature) {
        return res.status(400).send('Missing Monnify Signature Header');
    }
    const clientSecretKey = process.env.MONNIFY_SECRET;

    // Parse the JSON directly from req.body
    const requestBody = req.body;
    console.log(requestBody.eventData);

    const computedHash = crypto.createHmac('sha512', clientSecretKey)
        .update(JSON.stringify(requestBody))
        .digest('hex');

    if (monnifySignature === computedHash) {
        const { eventData } = requestBody;
        const { amountPaid: payment, paidOn: date, paymentReference } = eventData;
        const { reference } = eventData.product;

        if (processedTransactions.has(paymentReference)) {
            console.log('Transaction already processed:', reference);
            return res.status(200).send('Transaction already processed');
        }

        const result = await paymentSuccess(reference, payment, date);

        if (result === 'successful') {
            console.log('Monnify event is valid');
            processedTransactions.add(paymentReference);
            res.status(200).send('Monnify Event Verified');
        } else if (result === 'failed') {
            res.status(403).send('Bad request');
        }
    } else {
        console.log('Monnify event is invalid');
        res.status(401).send('Invalid Monnify Event');
    }
});


const settran = async (data) => {
    const { phonenumber, mobile_number, Status, plan_network, plan_name, plan_amount, create_date } = data;
    const parsedDate = new Date(create_date);
    const formattedDate = `${parsedDate.getFullYear()}-${(parsedDate.getMonth() + 1).toString().padStart(2, '0')}-${parsedDate.getDate().toString().padStart(2, '0')} 
    ${parsedDate.getHours().toString().padStart(2, '0')}:${parsedDate.getMinutes().toString().padStart(2, '0')}:${parsedDate.getSeconds().toString().padStart(2, '0')}`;
    const newamount = plan_amount * 1.09;
    try {
        const query = `INSERT INTO transactions (phonenumber, buynumber, status, price, date, network, size) VALUES (?,?,?,?,?,?,?)`;
        executeQuery(query, [phonenumber, mobile_number, Status, newamount, formattedDate, plan_network, plan_name,])
            .then((results) => {
                console.log('successful!', results);
            })
            .catch((error) => {
                console.log('error setting transaction')
            })
    } catch (error) {
        console.log(error)
    }
}
const setstran = async (data) => {
    const { phonenumber, mobile_number, Status, plan_network, plan_amount, create_date } = data;
    const parsedDate = new Date(create_date);
    const formattedDate = `${parsedDate.getFullYear()}-${(parsedDate.getMonth() + 1).toString().padStart(2, '0')}-${parsedDate.getDate().toString().padStart(2, '0')} 
    ${parsedDate.getHours().toString().padStart(2, '0')}:${parsedDate.getMinutes().toString().padStart(2, '0')}:${parsedDate.getSeconds().toString().padStart(2, '0')}`;

    try {
        const query = `INSERT INTO transactions (phonenumber, buynumber, status, price, date, network, size) VALUES (?,?,?,?,?,?,?)`;
        executeQuery(query, [phonenumber, mobile_number, Status, plan_amount, formattedDate, plan_network, 'Airtime'])
            .then((results) => {
                console.log('successful!', results);
            })
            .catch((error) => {
                console.log('error setting transaction')
            })
    } catch (error) {
        console.log(error)
    }
}
app.post('/api/v1/signup', async (req, res) => {
    const { firstname, lastname, phonenumber, password, email } = req.body;

    try {
        // Check if the phone number already exists
        const phoneQuery = 'SELECT COUNT(*) AS phoneCount FROM appusers WHERE phonenumber = ?';
        const emailQuery = 'SELECT COUNT(*) AS emailCount FROM appusers WHERE email = ?';

        const [phoneResults, emailResults] = await Promise.all([
            executeQuery(phoneQuery, [phonenumber]),
            executeQuery(emailQuery, [email])
        ]);

        const phoneCount = phoneResults[0].phoneCount;
        const emailCount = emailResults[0].emailCount;

        if (phoneCount > 0) {
            console.log('The phone number already exists');
            return res.send('phonenumber');
        }

        if (emailCount > 0) {
            console.log('The email already exists');
            return res.send('email');
        }

        const userid = generateUniqueUserID();
        const token = jwt.sign({ userid }, secretKey);

        const response = await getAccount(userid, email, firstname);

        if (!response) {
            return res.status(500).send('Error during user signup');
        }

        const mydata = response.data;

        const { bankName, accountNumber } = mydata;
        const customerbankname = 'Heydata Limited';

        const insertUserQuery =
            'INSERT INTO appusers (firstname, lastname, password, email, phonenumber, status, accountbalance, userid, bankname, bankaccountnumber, customerbankname) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

        await executeQuery(insertUserQuery, [firstname, lastname, password, email, phonenumber, 'active', 0, userid, bankName, accountNumber, customerbankname]);

        console.log('Inserted user into the database successfully');
        welcome(email, firstname);

        return res.status(200).json({ message: 'successful', token: token });
    } catch (error) {
        console.error('Error during user signup:', error);
        res.status(500).send('Error during user signup');
    }
});


app.post('/api/v1/createpin', async (req, res) => {
    const { pincode } = req.body;
    const userid = req.user.userid
    console.log('check user id out', userid)
    try {
        // Check if the phone number exists
        const phoneQuery = 'SELECT COUNT(*) AS phoneCount FROM appusers WHERE userid = ?';

        // Execute the query to count existing phone numbers
        executeQuery(phoneQuery, [userid])
            .then((phoneResults) => {
                const phoneCount = phoneResults[0].phoneCount;
                console.log('check phonecount out', phoneCount)

                if (phoneCount > 0) {
                    // If the phone number exists, insert the PIN code
                    const insertPinQuery = 'UPDATE appusers SET pin = ? WHERE userid = ?';

                    // Execute the query to update the PIN code
                    executeQuery(insertPinQuery, [pincode, userid])
                        .then(() => {
                            console.log('PIN code added successfully');
                            res.status(200).json({ message: 'successful' });
                        });
                } else {
                    console.log('The phone number does not exist');
                    res.status(200).json({ message: 'notfound' });
                }
            });
    } catch (error) {
        console.error('Error during PIN code creation:', error);
        res.status(500).send('Error during PIN code creation');
    }
});

app.post('/api/v1/login', async (req, res) => {
    const { phonenumber, password } = req.body;
    console.log('check number')
    const query = `SELECT userid, password FROM appusers WHERE phonenumber = ?`
    executeQuery(query, [phonenumber])
        .then(results => {
            if (results.length === 0) {
                return res.json({ error: 'User not found' });
            }

            const user = results[0];
            const { userid } = user;
            console.log('check numbe')
            const userpassword = user.password.toString()
            const intpassword = password.toString()
            if (userpassword !== intpassword) {
                console.log('Incorrect password', intpassword, userpassword);
                return res.json({ error: 'Incorrect password' });
            }
            else if (userpassword === intpassword) {
                console.log('check numberrrrr')
                const token = jwt.sign({ userid }, secretKey)

                console.log('Redirecting');
                return res.status(200).json({ message: 'successful', token: token });
            }
        })
        .catch((error) => {
            console.error('Error finding user credentials:', error);
            return res.json({ error: 'Internal server error' });
        })
});

const pinsetter = async (pin, userid) => {
    console.log('we also got here', pin, userid)
    try {
        const query = `UPDATE appusers SET pin = ? where userid = ?`;
        const results = await executeQuery(query, [pin, userid])
        const iknow = `approved`
        return iknow;
    }
    catch (error) {
        console.error(error)
        throw error;
    }
}
app.post('/api/v1/setpin', async (req, res) => {
    const { pin, password } = req.body;
    const userid = req.user.userid
    const intpass = parseInt(password, 10)
    console.log(pin, password)
    const query = `SELECT password FROM appusers WHERE userid = ?`
    executeQuery(query, [userid])
        .then(results => {
            if (results.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const user = results[0];
            console.log('we got here', user)
            const userpass = user.password
            if (userpass !== intpass) {
                console.log('Incorrect password');
                return res.status(200).json({ message: 'Incorrect Password' });
            }
            else if (userpass === intpass) {
                pinsetter(pin, userid)
                    .then(results => {
                        console.log(results)
                        if (results === 'approved') {
                            console.log('Redirecting');
                            return res.status(200).json({ message: 'successful' });
                        }
                        else {
                            return res.status(200).json({ message: 'Error setting Pin' });
                        }
                    })
                    .catch((error) => {
                        console.error(error)
                    })
            }
        })
        .catch((error) => {
            console.error('Error finding user credentials:', error);
            return res.status(500).json({ error: 'Internal server error' });
        })

});

const generateVerificationCode = () => {
    return Math.floor(100000 + Math.random() * 900000);
};

app.post('/api/v1/forgot', async (req, res) => {
    const { email } = req.body;
    console.log('Received the email:', email);

    const selectUserQuery = 'SELECT email,userid FROM appusers WHERE email = ?';
    executeQuery(selectUserQuery, [email])
        .then(results => {
            const user = results[0];
            console.log(user);
            if (user) {
                const userid = user.userid;
                const token = jwt.sign({ userid }, secretKey)
                const verificationCode = generateVerificationCode();
                forgot(email, verificationCode)
                    .then(rescode => {
                        const details = {
                            status: 200,
                            message: 'success',
                            token: token,
                            data: rescode
                        };
                        res.json(details);
                    })
                    .catch(error => {
                        console.error('Error in forgot function:', error);
                        res.status(500).json({ error: 'Internal server error' });
                    });

            }
            else {
                const details = {
                    ststus: 201,
                    message: 'failed',
                    data: 'The email doesnt exist'
                }
                res.json(details)
            }

        })
        .catch((error) => {
            console.error('Error finding user credentials:', error);
            return res.status(500).json({ error: 'Internal server error' });
        })
});

app.post('/api/v1/setpass', async (req, res) => {
    const { password } = req.body;
    const userid = req.user.userid;
    const query = `UPDATE appusers set password = ? WHERE userid = ?`;
    executeQuery(query, [password, userid])
        .then(results => {
            if (results) {
                return res.status(200).json({ success: true, message: 'Password Successfully set' });
            }
        })
        .catch((error) => {
            return res.status(200).send({ error: 'Internal server error' });
        })
});
/*
app.post('/api/v1/account', (req, res) => {


    const API_KEY = 'MK_TEST_N7915C78MR';
    const SECRET_KEY = 'NTVR7QVX0X1M3M4JX8BBRNDQV00JNLCT';

    const credentials = `${API_KEY}:${SECRET_KEY}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');
    const authHeader = `Basic ${encodedCredentials}`;

    const loginEndpoint = 'https://sandbox.monnify.com/api/v1/auth/login';

    axios.post(loginEndpoint, {}, {
        headers: {
            'Authorization': authHeader
        }
    })
        .then(response => {
            const accessToken = response.data.responseBody.accessToken;
            const phonenumber = req.body.phonenumber;

            const url = 'https://sandbox.monnify.com/api/v2/bank-transfer/reserved-accounts';
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            };
            const requestBody = {
                accountReference: phonenumber,
                accountName: 'Nokimobile',
                currencyCode: 'NGN',
                contractCode: '9750660067',
                customerEmail: 'peter@gmail.com',
                customerName: 'John Doe',
                getAllAvailableBanks: false,
                preferredBanks: ["035"]
            };
            axios.post(url, requestBody, { headers })
                .then(response => {
                    const responseData = response.data;
                    const accounts = responseData.responseBody.accounts;
                    console.log(accounts);
                    res.json(accounts[0]);
                })
                .catch(error => {
                    res.send('errorlog');
                    console.error(error);
                });
        })
        .catch(error => {
            console.error(error)
        });
});
*/

app.post('/api/v1/idan', async (req, res) => {
    const phonenumber = req.body.netcode;
    const url = `https://datastation.com.ng/api/network/`;
    const authToken = datasecret;

    try {
        const response = await axios.get(url, {
            headers: {
                'Authorization': `Token ${authToken}`,
                'Accept': 'application/json',
            }
        })
        if (phonenumber === '1') {
            const data = response.data.MTN_PLAN;
            console.log(data)
            const transformedData = data
                .filter(product => product.plan_type !== 'DATA COUPONS')
                .map(product => {
                    const { plan_amount, plan_network, id, plan, month_validate, plan_type } = product;
                    console.log(product);
                    const multipliedAmount = parseFloat(plan_amount) * 1.09;
                    const rounded = Math.round(multipliedAmount);
                    return { plan, month_validate, plan_type, network: plan_network, dataid: id, amount: rounded };
                });

            res.json(transformedData);
        }
        else if (phonenumber === '4') {
            const data = response.data.AIRTEL_PLAN;
            const transformedData = [];

            data.forEach(product => {
                const { plan_amount, plan_network, id, plan, month_validate, plan_type } = product;
                const multipliedAmount = parseFloat(plan_amount) * 1.09;
                const rounded = Math.round(multipliedAmount);
                transformedData.push({ plan, month_validate, plan_type, network: plan_network, dataid: id, amount: rounded });
            });

            res.json(transformedData);
            console.log(data)
        }
        else if (phonenumber === '2') {
            const data = response.data.GLO_PLAN;
            const transformedData = [];

            data.forEach(product => {
                const { plan_amount, plan_network, id, plan, month_validate, plan_type } = product;
                const multipliedAmount = parseFloat(plan_amount) * 1.09;

                const rounded = Math.round(multipliedAmount);
                transformedData.push({ plan, month_validate, plan_type, network: plan_network, dataid: id, amount: rounded });
            });

            res.json(transformedData);
        }
        else if (phonenumber === '3') {
            const data = response.data['9MOBILE_PLAN'];
            const transformedData = [];
            data.forEach(product => {
                const { plan_amount, plan_network, id, plan, month_validate, plan_type } = product;
                const multipliedAmount = parseFloat(plan_amount) * 1.09;

                const rounded = Math.round(multipliedAmount);
                transformedData.push({ plan, month_validate, plan_type, network: plan_network, dataid: id, amount: rounded });
            });

            res.json(transformedData);
        }
        else {
            const data = response.data;
            res.json(data)
            console.log(data)
        }
    }
    catch (error) {
        console.log(error)
    }
})

app.get('/api/v1/transactions', (req, res) => {
    const userid = req.user.userid;
    const query = `select phonenumber,userid from appusers where userid = ?`;
    executeQuery(query, [userid])
        .then(results => {
            console.log(results)
            const phonenumber = results[0].phonenumber
            const pquery = `select * from transactions where phonenumber = ?`
            executeQuery(pquery, [phonenumber])
                .then(results => {
                    console.log(results)
                    const transform = [];
                    const resu = results.reverse();
                    resu.forEach(element => {
                        const { buynumber, status, price, date, network, size } = element;
                        console.log(date)
                        const dateObject = new Date(date);
                        console.log(dateObject)
                        const year = dateObject.getFullYear();
                        const month = (dateObject.getMonth() + 1).toString().padStart(2, '0');
                        const day = dateObject.getDate().toString().padStart(2, '0');
                        const hours = dateObject.getHours().toString().padStart(2, '0');
                        const minutes = dateObject.getMinutes().toString().padStart(2, '0');
                        const seconds = dateObject.getSeconds().toString().padStart(2, '0');

                        const formattedDate = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;

                        console.log(formattedDate); // Output: "2023-08-22 12:58:24"

                        transform.push({ buynumber, status, price, date: formattedDate, network, size });
                    });
                    transform.map((idan) => {
                        console.log(idan)
                    });
                    res.json(transform);

                })
                .catch((error) => {
                    console.log(error)
                })

        })
        .catch((error) => {
            console.log(error)
        })
})
app.post('/api/v1/buyairtime', async (req, res) => {
    try {
        const { netcode, amount, number, pincode } = req.body;
        const userid = req.user.userid;
        console.log(req.body)
        const [userData] = await executeQuery('SELECT pin,phonenumber, accountbalance FROM appusers WHERE userid = ?', [userid]);

        if (!userData) {
            console.error('Account not found');
            return res.send('Account not found');
        }

        const { pin: mypin, phonenumber, accountbalance } = userData;
        console.log('this is userdata', accountbalance)

        if (mypin.toString() !== pincode.toString()) {
            console.log('Incorrect pin')
            return res.send('incorrect');
        }
        const balancc = Number(accountbalance);
        const amountcc = Number(amount)
        const newbalance = balancc - amountcc;

     if (newbalance < 0) {
    console.log('Insufficient funds');
    return res.status(200).json({ message: 'nonmoney' });
     } else if (balancc < amountcc) {
            console.log('Incorrect balance')
            return res.status(200).json({ message: 'nonmoney' });
        }

        else if (balancc >= amountcc) {

            const authToken = datasecret;
            const data = {
                "network": netcode,
                "amount": amount,
                "mobile_number": number,
                "Ported_number": true,
                "airtime_type": "VTU"
            };

            const config = {
                method: 'post',
                maxBodyLength: Infinity,
                url: 'https://datastation.com.ng/api/topup/',
                headers: {
                    'Authorization': `Token ${authToken}`,
                    'Accept': 'application/json',
                },
                data: data,
            };

            const response = await axios(config);
            const responseData = response.data;

            const { mobile_number, Status, plan_network, plan_amount, create_date } = responseData;
            const imade = { phonenumber, mobile_number, Status, plan_network, plan_amount, create_date };

            await setstran(imade);

            if (responseData.Status === 'successful') {
                const newbalance = balancc - amountcc;
                await executeQuery('UPDATE appusers SET accountbalance = ? WHERE userid = ?', [newbalance, userid]);
                res.json(responseData);
            } else {
                res.send(responseData.Status);
            }
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/api/v1/callbalance', async (req, res) => {
    const email = req.session.email;

    const db = await pool.getConnection();
    const selectBalanceQuery = 'SELECT accountbalance FROM appusers WHERE email = ?';
    db.query(selectBalanceQuery, [email], (err, results) => {
        if (err) {
            console.error('Error fetching account balance:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        db.release();
        const user = results[0];
        console.log(user);
        console.log('Fetched data', user);
        res.send(user);

    });
});

app.get('/api/v1/getuser', async (req, res) => {

    const userid = req.user.userid;
    console.log('Received phonenumber:', userid);

    const selectUserQuery = 'SELECT * FROM appusers WHERE userid = ?';
    executeQuery(selectUserQuery, [userid])
        .then(results => {
            const user = results[0];
            console.log(user);
            console.log('Redirecting');
            res.json(user);
        })
        .catch((error) => {
            console.error('Error finding user credentials:', error);
            return res.status(500).json({ error: 'Internal server error' });
        })
});


app.post('/api/v1/buydata', async (req, res) => {
    try {
        const { netcode, dataplan, number, dataamount, pincode } = req.body;

        console.log(netcode, dataplan, pincode, dataamount);
        const userid = req.user.userid

        const [userData] = await executeQuery('SELECT pin,phonenumber, accountbalance FROM appusers WHERE userid = ?', [userid]);

        if (!userData) {
            console.error('Account not found');
            return res.send('Account not found');
        }

        const { pin, phonenumber, accountbalance } = userData;
        const mypin = parseInt(pin, 10)
        const balance = parseInt(accountbalance, 10)
        console.log(mypin, balance)

        if (mypin.toString() !== pincode.toString()) {
            console.log('incorect pin')
            return res.status(200).json({ message: 'incorrect' });
        }
      const newbalance = balance - dataamount;

          if (newbalance < 0) {
         console.log('Insufficient funds');
        return res.status(200).json({ message: 'nonmoney' });
         } else if (balance < dataamount) {
            console.log('no money')
            return res.status(200).json({ message: 'nonmoney' });

        }
        else if (balance >= dataamount) {
            const authToken = datasecret;
            const data = {
                "network": netcode,
                "mobile_number": number,
                "plan": dataplan,
                "Ported_number": true
            };

            const config = {
                method: 'post',
                maxBodyLength: Infinity,
                url: 'https://datastation.com.ng/api/data/',
                headers: {
                    'Authorization': `Token ${authToken}`,
                    'Accept': 'application/json',
                },
                data: data,
            };

            const response = await axios(config);
            const responseData = response.data;

            const { mobile_number, Status, plan_network, plan_name, plan_amount, create_date } = responseData;
            const imade = { phonenumber, mobile_number, Status, plan_network, plan_name, plan_amount, create_date };

            await settran(imade);

            if (responseData.Status === 'successful') {
                const newbalance = balance - dataamount;
                await executeQuery('UPDATE appusers SET accountbalance = ? WHERE userid = ?', [newbalance, userid]);

                return res.status(200).json({ message: 'successful', number });
            } else {
                res.send(responseData.Status);
            }
        }


    } catch (error) {
        console.error(error);
        res.send('Internal Server Error');
    }
});

server.listen(port, () => {
    console.log(`Server started on port ${port}`);
});