using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static System.Net.Mime.MediaTypeNames;

namespace IdentityManager.Services
{
	public class MailJetEmailSender : IEmailSender
	{
		private readonly IConfiguration config;
		public MailJetOptions mailJetOptions;
		public MailJetEmailSender(IConfiguration config)
		{
			this.config = config;
		}

		public async Task SendEmailAsync(string email, string subject, string htmlMessage)
		{
			mailJetOptions = config.GetSection("MailJet").Get<MailJetOptions>();
			MailjetClient client = new MailjetClient(mailJetOptions.ApiKey,mailJetOptions.SecretKey);

			MailjetRequest request = new MailjetRequest
			{
				Resource = SendV31.Resource,
			}
			   .Property(Send.Messages, new JArray {
				new JObject {
				 {"From", new JObject {
				  {"Email", "sorbon_xn@proton.me"},
				  {"Name", "proton"}
				  }},
				 {"To", new JArray {
				  new JObject {
				   {"Email", email },
				   {"Name", "Sorbon"}
				   }
				  }},
				 {"Subject", subject},
				 {"HTMLPart", htmlMessage}
				}
				   });
			File.AppendAllText($"logs/emailMsg{DateTime.Now:ddMMyyyy}.txt", $"\n {email} : {JsonConvert.SerializeObject(htmlMessage)};");

			var response =  await client.PostAsync(request);
			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine(string.Format("Total: {0}, Count: {1}\n", response.GetTotal(), response.GetCount()));
				Console.WriteLine(response.GetData());
			}
			else
			{
				Console.WriteLine(string.Format("StatusCode: {0}\n", response.StatusCode));
				Console.WriteLine(string.Format("ErrorInfo: {0}\n", response.GetErrorInfo()));
				Console.WriteLine(response.GetData());
				Console.WriteLine(string.Format("ErrorMessage: {0}\n", response.GetErrorMessage()));
			}
		}
	}
}
