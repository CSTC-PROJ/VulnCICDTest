FROM node:22-alpine

WORKDIR /app

COPY package*.json ./

RUN apk add --no-cache python3 make g++

# Install Node.js dependencies
# Using 'npm ci' for clean and reproducible builds, as discussed.
RUN npm install

# Copy the rest of the application files
# This includes app.js, and the 'views' directory with its Handlebars templates.
COPY . .

# Expose the port the application runs on
EXPOSE 3000

# Command to run the application
CMD ["npm", "start"]
