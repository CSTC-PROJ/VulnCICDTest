# Use a very old and insecure Node.js Alpine image as the base.
# This version (Node.js 8) has many known vulnerabilities in the runtime itself.
FROM node:8-alpine

# Set the working directory inside the container
WORKDIR /app

# Using ADD here, which is generally considered a worse practice than COPY
# due to its implicit tar extraction and URL fetching capabilities,
# increasing potential for unexpected behavior or supply chain risks.
ADD package*.json ./

RUN apk add --no-cache python3 make g++

RUN npm install

# Copy the rest of the application files
# This includes app.js, and the 'views' directory with its Handlebars templates.
COPY . .

# Expose the port the application runs on
EXPOSE 3000

# The application will run as the root user inside the container by default,
# which is a security worst practice.
CMD ["npm", "start"]
