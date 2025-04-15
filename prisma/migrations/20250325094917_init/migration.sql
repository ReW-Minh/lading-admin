-- CreateTable
CREATE TABLE "alembic_version" (
    "version_num" VARCHAR(32) NOT NULL,

    CONSTRAINT "alembic_version_pkc" PRIMARY KEY ("version_num")
);

-- CreateTable
CREATE TABLE "blog" (
    "id" SERIAL NOT NULL,
    "author" VARCHAR NOT NULL,
    "route" VARCHAR NOT NULL,
    "content" TEXT NOT NULL,
    "created_time" INTEGER NOT NULL,
    "publish_time" INTEGER,
    "is_published" BOOLEAN NOT NULL,
    "title" VARCHAR NOT NULL,

    CONSTRAINT "blog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "episode" (
    "id" VARCHAR NOT NULL,
    "title" VARCHAR,
    "content" VARCHAR,
    "logo" VARCHAR,
    "player_url" VARCHAR,
    "publish_time" INTEGER,
    "duration" INTEGER,
    "episode_number" VARCHAR,
    "permalink" VARCHAR(500),

    CONSTRAINT "episode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "podcast_info" (
    "id" VARCHAR NOT NULL,
    "title" VARCHAR NOT NULL,
    "desc" VARCHAR NOT NULL,
    "logo" VARCHAR NOT NULL,
    "website" VARCHAR NOT NULL,

    CONSTRAINT "podcast_info_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user" (
    "id" SERIAL NOT NULL,
    "username" VARCHAR NOT NULL,
    "password" VARCHAR NOT NULL,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "blog_route_key" ON "blog"("route");

-- CreateIndex
CREATE INDEX "ix_blog_id" ON "blog"("id");

-- CreateIndex
CREATE INDEX "ix_episode_id" ON "episode"("id");

-- CreateIndex
CREATE INDEX "ix_podcast_info_id" ON "podcast_info"("id");

-- CreateIndex
CREATE UNIQUE INDEX "user_username_key" ON "user"("username");

-- CreateIndex
CREATE INDEX "ix_user_id" ON "user"("id");
