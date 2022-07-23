FROM library/postgres
COPY ./init.sql /docker-entrypoint-initdb.d/

# Use an official Elixir runtime as a parent image
FROM elixir:latest
LABEL maintainer="Gabriel Maia <gabrielmaialva33@gmail.com>"

# Install
RUN apt-get update && apt-get install -y libpq-dev

# Install Hex + Rebar
RUN mix do local.hex --force, local.rebar --force

# Create app directory and copy the Elixir projects into it
RUN mkdir /app
# Copy over source code
COPY . /app
# Set working directory
WORKDIR /app

# Set build ENV
ENV MIX_ENV=docker

# Install only required packages
RUN mix deps.get

# Compile all dependencies
RUN mix deps.compile

# Set and expose PORT environmental variable
ENV PORT ${PORT:-4000}

# Expose PORT
EXPOSE $PORT

#RUN min ecto.migrate

# Run entrypoint
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]