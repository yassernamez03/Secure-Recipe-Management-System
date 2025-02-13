# Recipe Management System

Welcome to the **Recipe Management System**, a Flask-based web application designed to help users manage, discover, and share their favorite recipes. This project is built with Flask, MongoDB, and various Flask extensions to provide a seamless user experience.

## Features

- **User Authentication**: Register, log in, and manage your account securely.
- **Recipe Management**: Add, edit, and delete your recipes.
- **Search Functionality**: Search for recipes by name, ingredients, or category.
- **Responsive Design**: Access the app on any device, including desktops, tablets, and mobile phones.
- **Rate and Review**: Logged-in users can rate and review recipes.
- **Secure Password Handling**: Passwords are securely hashed using Flask-Bcrypt.
- **Two-Factor Authentication (2FA)**: Enhanced security with TOTP-based two-factor authentication.
- **Password Recovery**: Securely recover your account with email-based password reset.

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript (with Jinja2 templating)
- **Database**: MongoDB (via Flask-PyMongo)
- **Authentication**: Flask-Login, Flask-Bcrypt
- **Form Handling**: Flask-WTF, WTForms
- **Rate Limiting**: Flask-Limiter
- **Two-Factor Authentication**: PyOTP
- **Other Libraries**: Rich (for console output), Flask-Talisman (for security headers), Flask-QRcode (for QR code generation)

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yassernamez03/Recipe-Management-System.git
   cd Recipe-Management-System
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv myvenv
   .\myvenv\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up Environment Variables**

   Create a `.env` file in the root directory and add the following environment variables:

   ```env
   SECRET_KEY=your_secret_key
   MONGO_URI=your_mongodb_uri
   SENDINBLUE_API_KEY=your_sendinblue_api_key
   GROQ_API_KEY=your_groq_api_key
   ```

5. **Run the Application**

   ```bash
   flask run
   ```

## Usage

- **Home Page**: Visit the home page to browse featured recipes.
- **Search**: Use the search bar to find recipes by name, ingredients, or category.
- **Recipe Details**: Click on a recipe to view its details, including ingredients, instructions, and user reviews.
- **User Dashboard**: Log in to access your saved recipes, add new recipes, and manage your account.
- **Rate and Review**: Logged-in users can rate and review recipes.
- **Two-Factor Authentication**: Enable or disable 2FA for added security.
- **Password Recovery**: Reset your password securely via email.

## API Endpoints (Optional)

If your app includes an API, you can document the endpoints here. For example:

- `GET /api/recipes`: Get a list of all recipes.
- `GET /api/recipes/<id>`: Get details of a specific recipe.
- `POST /api/recipes`: Add a new recipe (requires authentication).

## Contributing

We welcome contributions! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.

Please ensure your code follows the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to the Flask community for their excellent documentation and resources.
- Inspiration for this project came from a love of cooking and sharing recipes with friends and family.

## Contact

If you have any questions or suggestions, feel free to reach out:

- **GitHub**: [yassernamez03](https://github.com/yassernamez03)
- **Email**: [namezyasser5@gmail.com](mailto:namezyasser5@gmail.com)

---

Happy Cooking! 🍳