import express from "express";
import path from "path";
import jsonfile from "jsonfile";
import bcrypt from "bcrypt";

const app = express();
const usersfile = path.join(process.cwd(), "./src/data/users.json");

app.set("view engine", "ejs");
app.set("views", "src/views");

app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
    res.render("home");
});
app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/login", (req, res, next) => {
    jsonfile.readFile(usersfile, (err, data) => {
        if (err) return next(err);

        const user = data.find((user) => user.username === req.body.username);

        // s'il ne trouve pas l'utilisateur, il faut renvoyer une erreur 401
        if (!user) {
            const err = new Error();
            err.status = 401;
            return next(err);
        }
        // sinon il existe, on vérifie le mot de passe
        bcrypt.compare(req.body.password, user.password, (err, same) => {
            // s'il y a une erreur, on la renvoie
            if (err) return next(err);

            // si les mot de passe ne correspondent pas, on renvoie une erreur 401
            if (!same) {
                const err = new Error();
                err.status = 401;
                next(err);
            }

            // sinon on redirige vers la page d'accueil
            res.redirect("/");
        });
    });
});

app.post("/register", (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) return next(err);

        const newUser = {
            username: req.body.username,
            password: hash,
        };

        jsonfile.readFile(usersfile, (err, data) => {
            if (err) {
                console.error(err);
                data = [];
            }

            data.push(newUser);

            jsonfile.writeFile(
                usersfile,
                data,
                { spaces: 4, EOL: "\r\n" },
                (err) => {
                    if (err) return next(err);

                    res.redirect("/login");
                }
            );
        });
    });
});



// pour gérer les erreurs avec le middleware Express, il faut définir une fonction avec 4 paramètres
app.use((err, req, res, next) => {
    console.error(err.status);
    let status = err.status || 500;
    let message = "";

    switch (status) {
        case 500:
            message = "An error occurred while processing your request.";
            break;
        case 401:
            message = "Invalid credentials.";
            break;
        default:
            message = "An unexpected error occurred.";
            break;
    }

    res.status(status).send(message);
});

app.listen(3000, () => {
    console.log("Server started (http://localhost:3000/) !");
});
