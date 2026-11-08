# DORA Incident Agent

A prototype that checks whether an IT incident at a made-up bank, Rheinbank, is "major" under the EU's Digital Operational Resilience Act (DORA). An AI agent collects the missing facts from simulated bank systems, fixed rules taken from the law make the decision, and a person approves the draft initial notification.

**Work in progress.** Not every part is built yet, and no results are claimed here. The full README, with measured results and limits, comes when the build is finished.

**Runs in Google Colab only.** Open `notebooks/colab.ipynb` in Colab, add your own Groq key in Colab Secrets as `GROQ_API_KEY`, and run the cells. There is no local launch and no public link.

All data is synthetic. This is not legal advice.
