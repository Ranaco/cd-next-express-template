# Next.js + Express + Prisma Authentication Template

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/Code-Decoders/cd-next-express-template/workflows/CI/badge.svg)](https://github.com/Code-Decoders/cd-next-express-template/actions)
[![GitHub issues](https://img.shields.io/github/issues/Code-Decoders/cd-next-express-template)](https://github.com/Code-Decoders/cd-next-express-template/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)
[![GitHub Stars](https://img.shields.io/github/stars/Code-Decoders/cd-next-express-template)](https://github.com/Code-Decoders/cd-next-express-template/stargazers)

A modern full-stack template with Next.js, Express, and Prisma, featuring a comprehensive authentication system, user management, and role-based access control.

## Features

- Custom Express server with Next.js integration
- Authentication system with session management
- Role-based access control
- Rate limiting for security
- PostgreSQL database with Prisma ORM
- Cookie-based authentication

## Demo

![Authentication Demo](https://via.placeholder.com/800x400?text=Authentication+System+Demo)

## Getting Started

### Prerequisites

- Node.js 18+ 
- PostgreSQL database

### Installation Options

#### Option 1: Use as GitHub Template

1. Click the "Use this template" button at the top of the repository
2. Name your new repository and create it
3. Clone your new repository locally

#### Option 2: Clone Manually

```bash
git clone https://github.com/Code-Decoders/cd-next-express-template.git
cd nextjs-express-prisma-auth-template
```

### Setup

1. Install dependencies:

```bash
npm install
# or
yarn install
```

2. Configure environment variables:
   
Copy the `.env.example` to `.env` and update the database connection string and other settings.

```bash
# Example .env file
DATABASE_URL="postgresql://username:password@localhost:5432/your_database"
JWT_SECRET="your-jwt-secret"
```

3. Initialize the database:

```bash
# Generate Prisma client
npm run prisma:generate
# or
yarn prisma:generate

# Run migrations
npm run prisma:migrate
# or
yarn prisma:migrate

# Seed the database with initial data
npm run db:seed
# or
yarn db:seed
```

4. Start the development server:

```bash
npm run dev
# or
yarn dev
```

The application will be available at [http://localhost:3000](http://localhost:3000).

## Project Structure

- `/pages` - Next.js pages and API routes
- `/public` - Static assets
- `/prisma` - Prisma schema and migrations
- `/server` - Express server code
  - `/controllers` - Route controllers
  - `/middleware` - Custom middleware
  - `/routers` - Express routers
  - `/utils` - Utility functions
  - `index.js` - Main server entry point

## API Routes

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user

### Users

- `GET /api/users` - Get all users (admin only)
- `GET /api/users/:id` - Get user by ID (admin only)
- `PUT /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

## Testing

Test the API endpoints:

```bash
npm run test:api
# or
yarn test:api
```

## Scripts

- `dev` - Start development server
- `build` - Build for production
- `start` - Start production server
- `lint` - Run ESLint
- `prisma:generate` - Generate Prisma client
- `prisma:migrate` - Run database migrations
- `prisma:studio` - Open Prisma Studio
- `db:seed` - Seed the database with initial data
- `test:api` - Test API endpoints

## Authentication Features

- Email/Password authentication
- OTP (One-Time Password) authentication
- Email verification
- Password reset
- Role-based access control (RBAC)
- Session management with refresh tokens
- Rate limiting to prevent brute force attacks
- Comprehensive activity and security logging

## Deployment

### Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FCode-Decoders%2Fcd-next-express-template&project-name=my-nextjs-app&repository-name=my-nextjs-app)

⚠️ **Note:** Since this template uses a custom Express server, you'll need to adjust the deployment configuration to use Vercel's serverless functions or deploy the Express server separately.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository.

---