FROM node:20-alpine
WORKDIR /app

COPY package.json yarn.lock .yarnrc.yml ./

RUN yarn install

COPY . .

CMD ["yarn", "start"]
