build-local-image:
    # build the docker image locally, without involving wrangler, use to prototype your build
    bun install
    docker build -t chamberspy:latest .

run-local-image:
    # run the local docker image, to validate your build
    docker run -it -p 30000:30000 chamberspy:latest

dev:
    # use wrangler to build the image (not same as local image) and run it in simulator
    #   see miniflare: https://developers.cloudflare.com/workers/testing/miniflare/
    wrangler dev --port 30000

deploy:
    # if wrangler dev looks good, you are ready to deploy
    wrangler deploy

deploy-dry-run:
    wrangler deploy --dry-run
