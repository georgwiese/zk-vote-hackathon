# See https://blog.ruanbekker.com/blog/2019/09/14/running-vs-code-in-your-browser-with-docker/
FROM ruanbekker/vscode:python-3.7

RUN curl -LSfs get.zokrat.es | sh
ENV PATH="/root/.zokrates/bin:${PATH}"

COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

CMD ["/docker-entrypoint.sh"]