@rest service email {
   @POST
   action sendEmail(to: String, subject: String, content: String);
}
