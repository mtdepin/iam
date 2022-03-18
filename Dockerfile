FROM 192.168.1.214:443/gobase/ubuntu:20.04
RUN  mkdir -p /iam /iam/logs
ENV WORK_HOME /iam
COPY mt-iam /iam
COPY ./conf /iam/conf
WORKDIR $WORK_HOME
VOLUME /iam/conf
VOLUME /iam/logs
EXPOSE 10001
CMD ["./mt-iam"]