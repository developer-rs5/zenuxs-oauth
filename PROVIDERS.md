# Zenuxs OAuth - Social Providers Documentation

This document outlines the complete list of available methods and events for each of the 8 supported social providers in the Zenuxs SDK.

When using these SDK wrappers, the SDK securely authenticates the requests via your session, and forwards them to the underlying social platforms.

---

## 1. Discord (`oauth.discord()`)

**Initialization:**
```javascript
const discord = oauth.discord();
```

**Methods:**
- `await discord.getProfile()`: Fetch the user's Discord profile data.
- `await discord.getGuilds()`: Fetch the user's list of joined servers (guilds).
- `await discord.sendMessage(channelId, message)`: Send a message to a specific Discord channel as the user.

**Events to listen for:**
```javascript
discord.on('profile_fetched', (data) => console.log(data));
discord.on('guilds_fetched', (data) => console.log(data));
discord.on('message_sent', (data) => console.log(data));
```

---

## 2. GitHub (`oauth.github()`)

**Initialization:**
```javascript
const github = oauth.github();
```

**Methods:**
- `await github.getProfile()`: Fetch the authenticated user's GitHub profile.
- `await github.getRepos()`: Fetch the user's public and private repositories.
- `await github.createIssue(repoName, { title, body })`: Open a new issue in a specified repository.

**Events to listen for:**
```javascript
github.on('profile_fetched', (data) => console.log(data));
github.on('repos_fetched', (data) => console.log(data));
github.on('issue_created', (data) => console.log(data));
```

---

## 3. Google (`oauth.google()`)

**Initialization:**
```javascript
const google = oauth.google();
```

**Methods:**
- `await google.getProfile()`: Fetch the Google user's profile and email.
- `await google.getDriveFiles()`: List the files in the user's Google Drive.
- `await google.sendEmail({ to, subject, body })`: Send an email on behalf of the user using Gmail API.

**Events to listen for:**
```javascript
google.on('profile_fetched', (data) => console.log(data));
google.on('files_fetched', (data) => console.log(data));
google.on('email_sent', (data) => console.log(data));
```

---

## 4. Twitter / X (`oauth.x()` or `oauth.twitter()`)

**Initialization:**
```javascript
const x = oauth.x(); // or oauth.twitter()
```

**Methods:**
- `await x.getProfile()`: Fetch the user's Twitter profile.
- `await x.getTweets()`: Fetch the user's recent tweets.
- `await x.createTweet(text)`: Publish a new tweet.
- `await x.likeTweet(tweetId)`: Like a specific tweet.

**Events to listen for:**
```javascript
x.on('profile_fetched', (data) => console.log(data));
x.on('tweets_fetched', (data) => console.log(data));
x.on('tweet_created', (data) => console.log(data));
x.on('tweet_liked', (data) => console.log(data));
```

---

## 5. LinkedIn (`oauth.linkedin()`)

**Initialization:**
```javascript
const linkedin = oauth.linkedin();
```

**Methods:**
- `await linkedin.getProfile()`: Fetch the user's LinkedIn profile.
- `await linkedin.getConnections()`: Fetch the user's first-degree connections.
- `await linkedin.createPost(content)`: Publish a new post/share on the user's LinkedIn feed.

**Events to listen for:**
```javascript
linkedin.on('profile_fetched', (data) => console.log(data));
linkedin.on('connections_fetched', (data) => console.log(data));
linkedin.on('post_created', (data) => console.log(data));
```

---

## 6. Facebook (`oauth.facebook()`)

**Initialization:**
```javascript
const facebook = oauth.facebook();
```

**Methods:**
- `await facebook.getProfile()`: Fetch the user's Facebook profile.
- `await facebook.getPages()`: List the Facebook Pages managed by the user.
- `await facebook.createPost(pageId, content)`: Publish a post to a specific Facebook Page.

**Events to listen for:**
```javascript
facebook.on('profile_fetched', (data) => console.log(data));
facebook.on('pages_fetched', (data) => console.log(data));
facebook.on('post_created', (data) => console.log(data));
```

---

## 7. Instagram (`oauth.instagram()`)

**Initialization:**
```javascript
const instagram = oauth.instagram();
```

**Methods:**
- `await instagram.getProfile()`: Fetch the user's Instagram profile.
- `await instagram.getMedia()`: Fetch the user's recent photos and videos.
- `await instagram.publishMedia(mediaUrl, caption)`: Publish a new photo/video to the user's feed.

**Events to listen for:**
```javascript
instagram.on('profile_fetched', (data) => console.log(data));
instagram.on('media_fetched', (data) => console.log(data));
instagram.on('media_published', (data) => console.log(data));
```

---

## 8. YouTube (`oauth.youtube()`)

**Initialization:**
```javascript
const youtube = oauth.youtube();
```

**Methods:**
- `await youtube.getProfile()`: Fetch the user's YouTube profile.
- `await youtube.getChannels()`: List the user's YouTube channels.
- `await youtube.getVideos(channelId)`: Fetch recent videos uploaded to a specific channel.
- `await youtube.likeVideo(videoId)`: Rate/Like a specific YouTube video.

**Events to listen for:**
```javascript
youtube.on('profile_fetched', (data) => console.log(data));
youtube.on('channels_fetched', (data) => console.log(data));
youtube.on('videos_fetched', (data) => console.log(data));
youtube.on('video_liked', (data) => console.log(data));
```
