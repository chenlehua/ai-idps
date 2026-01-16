FROM node:18-alpine

WORKDIR /app

# 配置国内 Alpine APK 源（阿里云）
RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.aliyun.com|g' /etc/apk/repositories

# 配置国内 npm 源（淘宝）
RUN npm config set registry https://registry.npmmirror.com

COPY package.json /app/package.json
RUN npm install

COPY . /app

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
