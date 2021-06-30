require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const keypairoom = require('@dyne/keypairoom');

if (typeof localStorage === "undefined" || localStorage === null) {
    var LocalStorage = require('node-localstorage').LocalStorage;
    localStorage = new LocalStorage('./scratch');
}

const app = express();

// middleware / routing
app.set('view engine', 'pug');
app.use(bodyParser.urlencoded({ extended: true}));
app.use(express.static('public'));

app.get('/', function(request, response) {
    return response.render('homepage');
});

app.get('/homepage', function(request, response) {
    return response.render('homepage');
});

app.post('/generate-keypair', async function(request, response) {
    const safetyQuestions = keypairoom.getSafetyQuestions('en_GB');
    const data = request.body;
    let errors = '';
    let pbkdf = {};
    let keypair = {};
    let publicKey = '';
    let privateKey = '';

    if (data.formSent) {
        // Check the email
        if (!data.email) errors += "Please enter the e-mail. ";

        // Check the password
        //if (!data.password) errors += "Please enter the password. ";

        // Check answers
        let answers = 0;
        if (data.question1) answers++;
        if (data.question2) answers++;
        if (data.question3) answers++;
        if (data.question4) answers++;
        if (data.question5) answers++;

        if (answers !== 3) errors += "Please only answer 3 questions. ";

        // If no errors generate the PBKDF
        if (!errors) {
            // The client will send e-mail to the server which will generate the PBKDF and return it to the client.
            // Create an endpoint that accepts userData, generates the PBKDF and returns it.

            //*** USUALLY TO BE EXECUTED ON THE SERVER ***
            const userData = {
                email: data.email
            };

            pbkdf = await keypairoom.createPBKDF(userData);
            //********************************************

            // Set the answers (if string is empty is necessary set it to 'null', Zenroom don't accept null or empty strings)
            let answer1 = 'null';
            let answer2 = 'null';
            let answer3 = 'null';
            let answer4 = 'null';
            let answer5 = 'null';

            if (data.question1) answer1 = data.question1;
            if (data.question2) answer2 = data.question2;
            if (data.question3) answer3 = data.question3;
            if (data.question4) answer4 = data.question4;
            if (data.question5) answer5 = data.question5;

            let answers = {
                question1: answer1,
                question2: answer2,
                question3: answer3,
                question4: answer4,
                question5: answer5,
            };

            // Sanitize the answers
            answers = keypairoom.sanitizeAnswers(answers);

            // Generate the keypair
            keypair = await keypairoom.recoveryKeypair(answers, pbkdf.key_derivation, "user");

            publicKey = keypair.user.keypair.public_key;
            privateKey = keypair.user.keypair.private_key;

            // Save in localStorage the PBKDF and the public key (probably you need to save in your database)
            localStorage.setItem('pbkdf', pbkdf.key_derivation);
            localStorage.setItem('publicKey', publicKey);
        }
    }

    return response.render('generate-keypair', { safetyQuestions: safetyQuestions, data: data, errors: errors, pbkdf: pbkdf, keypair: keypair, publicKey: publicKey, privateKey: privateKey });
});

app.post('/recover-keypair', async function(request, response) {
    const safetyQuestions = keypairoom.getSafetyQuestions('en_GB');
    const data = request.body;
    let errors = '';
    const savedPBKDF = localStorage.getItem('pbkdf');
    const savedPublicKey = localStorage.getItem('publicKey');
    let verifyAnswersResults = 'keypair-not-generated';

    if (savedPBKDF && savedPublicKey) {
        verifyAnswersResults = '';
    }

    if (data.formSent) {
        // Check the email
        if (!data.email) errors += "Please enter the e-mail. ";

        // Check answers
        let answers = 0;
        if (data.question1) answers++;
        if (data.question2) answers++;
        if (data.question3) answers++;
        if (data.question4) answers++;
        if (data.question5) answers++;

        if (answers !== 3) errors += "Please only answer 3 questions. ";

        // If no errors generate the PBKDF
        if (!errors) {
            // Set the answers (if string is empty is necessary set it to 'null', Zenroom don't accept null or empty strings)
            let answer1 = 'null';
            let answer2 = 'null';
            let answer3 = 'null';
            let answer4 = 'null';
            let answer5 = 'null';

            if (data.question1) answer1 = data.question1;
            if (data.question2) answer2 = data.question2;
            if (data.question3) answer3 = data.question3;
            if (data.question4) answer4 = data.question4;
            if (data.question5) answer5 = data.question5;

            let answers = {
                question1: answer1,
                question2: answer2,
                question3: answer3,
                question4: answer4,
                question5: answer5,
            };

            // Sanitize the answers
            answers = keypairoom.sanitizeAnswers(answers);

            // Verify the answers
            const answersMatch = await keypairoom.verifyAnswers(answers, data.savedPBKDF, 'user', data.savedPublicKey);
            
            if (answersMatch) {
                verifyAnswersResults = 'answers-match';
            } else {
                verifyAnswersResults = 'answers-not-match';
            }
        }
    }

    return response.render('recover-keypair', { safetyQuestions: safetyQuestions, data: data, errors: errors, savedPBKDF: savedPBKDF, savedPublicKey: savedPublicKey, verifyAnswersResults: verifyAnswersResults });
});

app.listen(3000, function() {
    console.log('Server is running on port 3000');
});