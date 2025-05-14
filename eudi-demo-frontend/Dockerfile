FROM node:18-alpine

# Install browser-sync globally
RUN npm install -g browser-sync

WORKDIR /app

EXPOSE 4400

# Default command: watch current dir and reload on change
CMD ["browser-sync", "start", "--server", "--files", ".", "--port", "4400", "--host", "0.0.0.0"]
