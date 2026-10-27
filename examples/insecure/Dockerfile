# A02 and A03 example: a quick first Dockerfile. Do not use it.
# Floating tag, full build image, every file in the build context, npm install
# (with install scripts), npm in the final image, and the root user.
FROM node:24
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
